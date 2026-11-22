package local.enterprise.iam;

import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Non-interactive step placed after an MFA authenticator. It records which factor was used and the
 * resulting internal assurance level (AAL1-AAL3) as user-session notes (mapped into the tokens as the
 * "mfa_method" and "aal" claims) and adds mfa_method to the LOGIN event for SIEM correlation.
 */
public class AssuranceNoteAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String method = "unknown";
        String aal = "AAL1";
        String requiredType = null;
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        if (cfg != null && cfg.getConfig() != null) {
            Map<String, String> c = cfg.getConfig();
            method = c.getOrDefault(AssuranceNoteAuthenticatorFactory.CFG_METHOD, method);
            aal = c.getOrDefault(AssuranceNoteAuthenticatorFactory.CFG_AAL, aal);
            requiredType = c.get(AssuranceNoteAuthenticatorFactory.CFG_CREDENTIAL_TYPE);
        }
        // During first-time enrolment the preceding authenticator was skipped (a required action registers
        // the credential after the flow). Keep the notes written by the initial OTP step in that case.
        if (requiredType != null && !requiredType.isBlank() && context.getUser() != null
                && context.getUser().credentialManager().getStoredCredentialsByTypeStream(requiredType).findAny().isEmpty()) {
            context.success();
            return;
        }
        context.getAuthenticationSession().setUserSessionNote("mfa_method", method);
        context.getAuthenticationSession().setUserSessionNote("aal", aal);
        context.getEvent().detail("mfa_method", method);
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
