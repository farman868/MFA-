package local.enterprise.iam;

import java.util.stream.Stream;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Condition: true when the user has no strong MFA credential yet (no TOTP, no WebAuthn key, no passkey).
 * Used to require an SMS/Email OTP as the INITIAL factor before a user may enrol an authenticator,
 * so a stolen password alone cannot be used to register an attacker-controlled authenticator.
 */
public class NoMfaEnrolledCondition implements ConditionalAuthenticator {

    static final String[] STRONG_TYPES = {"otp", "webauthn", "webauthn-passwordless"};

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            return false;
        }
        return Stream.of(STRONG_TYPES).noneMatch(type ->
                user.credentialManager().getStoredCredentialsByTypeStream(type).findAny().isPresent());
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Conditions are evaluated through matchCondition(); nothing to render.
    }

    @Override
    public void action(AuthenticationFlowContext context) {
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
