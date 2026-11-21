package local.enterprise.iam;

import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Second-factor authenticator for the accessibility / no-smartphone fallback tier.
 *
 * Stage 1 ("choose"): the user picks SMS or Email (accessible button choice, no timers on this page).
 * Stage 2 ("verify"): the bridge sends a 6-digit OTP; the user submits it; the bridge verifies it.
 *
 * Every failed verification is recorded as a Keycloak LOGIN_ERROR event with error="invalid_otp"
 * and mfa_method="sms-otp"/"email-otp", so it reaches the SIEM and counts toward brute-force lockout.
 */
public class BridgeOtpAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(BridgeOtpAuthenticator.class);

    static final String TEMPLATE = "bridge-otp.ftl";
    static final String NOTE_CHALLENGE = "bridge-otp.challenge";
    static final String NOTE_CHANNEL = "bridge-otp.channel";
    static final String NOTE_DESTINATION = "bridge-otp.masked-destination";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        clearChallenge(context.getAuthenticationSession());
        context.challenge(render(context, "choose", null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        String action = form.getFirst("action");
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if ("send".equals(action)) {
            sendCode(context, form.getFirst("channel"));
        } else if ("resend".equals(action)) {
            sendCode(context, authSession.getAuthNote(NOTE_CHANNEL));
        } else if ("verify".equals(action)) {
            verifyCode(context, form.getFirst("otp"));
        } else {
            clearChallenge(authSession);
            context.challenge(render(context, "choose", null));
        }
    }

    private void sendCode(AuthenticationFlowContext context, String channel) {
        UserModel user = context.getUser();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        if (!"sms".equals(channel) && !"email".equals(channel)) {
            context.challenge(render(context, "choose", "Choose how you want to receive your code."));
            return;
        }
        String destination = "sms".equals(channel) ? user.getFirstAttribute("mobile") : user.getEmail();
        if (destination == null || destination.isBlank()) {
            context.challenge(render(context, "choose",
                    "No " + ("sms".equals(channel) ? "mobile number" : "email address")
                            + " is registered for your account. Choose another option or contact the IT service desk."));
            return;
        }

        Map<String, Object> body = new HashMap<>();
        body.put("username", user.getUsername());
        body.put("user_id", user.getId());
        body.put("realm", context.getRealm().getName());
        body.put("client_id", authSession.getClient() != null ? authSession.getClient().getClientId() : "");
        body.put("channel", channel);
        body.put("destination", destination);
        body.put("ip_address", context.getConnection().getRemoteAddr());

        try {
            Map<String, Object> response = client(context).post("/otp/send", body);
            int status = BridgeClient.status(response);
            if (status == 200) {
                authSession.setAuthNote(NOTE_CHALLENGE, BridgeClient.str(response, "challenge_id"));
                authSession.setAuthNote(NOTE_CHANNEL, channel);
                authSession.setAuthNote(NOTE_DESTINATION, BridgeClient.str(response, "masked_destination"));
                context.challenge(render(context, "verify", null));
            } else if (status == 429) {
                String stage = authSession.getAuthNote(NOTE_CHALLENGE) != null ? "verify" : "choose";
                context.challenge(render(context, stage,
                        "Too many codes were requested. Wait about a minute, then try again. "
                                + "If you did not request these codes, contact the IT service desk."));
            } else {
                LOG.warnf("mfa-otp-bridge /otp/send returned HTTP %d for user %s", status, user.getUsername());
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                        render(context, "choose", "The code could not be sent. Try the other option or contact the IT service desk."));
            }
        } catch (Exception e) {
            LOG.error("mfa-otp-bridge unreachable during /otp/send", e);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    render(context, "choose", "The verification service is unavailable. Contact the IT service desk."));
        }
    }

    private void verifyCode(AuthenticationFlowContext context, String otp) {
        UserModel user = context.getUser();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String challengeId = authSession.getAuthNote(NOTE_CHALLENGE);
        String channel = authSession.getAuthNote(NOTE_CHANNEL);
        String method = ("sms".equals(channel) ? "sms" : "email") + "-otp";

        if (challengeId == null) {
            context.challenge(render(context, "choose", "Your code expired. Request a new code."));
            return;
        }
        String code = otp == null ? "" : otp.replaceAll("\\s", "");

        Map<String, Object> body = new HashMap<>();
        body.put("challenge_id", challengeId);
        body.put("code", code);
        body.put("username", user.getUsername());
        body.put("ip_address", context.getConnection().getRemoteAddr());

        try {
            Map<String, Object> response = client(context).post("/otp/verify", body);
            if (BridgeClient.status(response) == 200 && Boolean.TRUE.equals(response.get("valid"))) {
                // Internal assurance scale: SMS (possession of the registered phone) = AAL2; email = AAL1, because a
                // mailbox is commonly protected by the same password the attacker may already hold.
                authSession.setUserSessionNote("mfa_method", method);
                authSession.setUserSessionNote("aal", "sms".equals(channel) ? "AAL2" : "AAL1");
                context.getEvent().detail("mfa_method", method);
                clearChallenge(authSession);
                context.success();
                return;
            }

            String error = BridgeClient.str(response, "error");
            if (error == null) {
                error = "invalid_otp";
            }
            context.getEvent().user(user).detail("mfa_method", method).error(error);

            if ("expired_code".equals(error) || "too_many_attempts".equals(error)) {
                clearChallenge(authSession);
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                        render(context, "choose", "That code can no longer be used. Request a new code."));
            } else {
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        render(context, "verify", "The code is not correct. Check the code and try again."));
            }
        } catch (Exception e) {
            LOG.error("mfa-otp-bridge unreachable during /otp/verify", e);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    render(context, "verify", "The verification service is unavailable. Contact the IT service desk."));
        }
    }

    private Response render(AuthenticationFlowContext context, String stage, String error) {
        UserModel user = context.getUser();
        String mobile = user.getFirstAttribute("mobile");
        String email = user.getEmail();
        LoginFormsProvider form = context.form()
                .setAttribute("bridgeStage", stage)
                .setAttribute("hasMobile", mobile != null && !mobile.isBlank())
                .setAttribute("hasEmail", email != null && !email.isBlank())
                .setAttribute("maskedMobile", maskPhone(mobile))
                .setAttribute("maskedEmail", maskEmail(email))
                .setAttribute("sentTo", nz(context.getAuthenticationSession().getAuthNote(NOTE_DESTINATION)))
                .setAttribute("sentChannel", nz(context.getAuthenticationSession().getAuthNote(NOTE_CHANNEL)))
                .setAttribute("bridgePurpose", purpose(context));
        if (error != null) {
            form.setError(error);
        }
        return form.createForm(TEMPLATE);
    }

    private static String purpose(AuthenticationFlowContext context) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        String p = cfg != null && cfg.getConfig() != null ? cfg.getConfig().get(BridgeOtpAuthenticatorFactory.CFG_PURPOSE) : null;
        return "enrolment".equals(p) ? "enrolment" : "signin";
    }

    private BridgeClient client(AuthenticationFlowContext context) {
        String url = null;
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        if (cfg != null && cfg.getConfig() != null) {
            url = cfg.getConfig().get(BridgeOtpAuthenticatorFactory.CFG_BRIDGE_URL);
        }
        if (url == null || url.isBlank()) {
            url = System.getenv().getOrDefault("MFA_BRIDGE_URL", "http://mfa-otp-bridge:8000");
        }
        return new BridgeClient(url, System.getenv("MFA_BRIDGE_API_KEY"));
    }

    private static void clearChallenge(AuthenticationSessionModel s) {
        s.removeAuthNote(NOTE_CHALLENGE);
        s.removeAuthNote(NOTE_DESTINATION);
    }

    static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "";
        }
        int at = email.indexOf('@');
        return email.charAt(0) + "***" + email.substring(at);
    }

    static String maskPhone(String phone) {
        if (phone == null || phone.length() < 4) {
            return "";
        }
        return "*******" + phone.substring(phone.length() - 3);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        String mobile = user.getFirstAttribute("mobile");
        return (user.getEmail() != null && !user.getEmail().isBlank()) || (mobile != null && !mobile.isBlank());
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Delivery addresses come from the directory (LDAP); nothing for the user to enrol here.
    }

    @Override
    public void close() {
    }
}
