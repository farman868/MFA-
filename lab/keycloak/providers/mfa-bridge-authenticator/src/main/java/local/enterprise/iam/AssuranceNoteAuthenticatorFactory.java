package local.enterprise.iam;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class AssuranceNoteAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "mfa-assurance-note";
    public static final String CFG_METHOD = "mfa.method";
    public static final String CFG_AAL = "aal";
    public static final String CFG_CREDENTIAL_TYPE = "credential.type";

    private static final AssuranceNoteAuthenticator SINGLETON = new AssuranceNoteAuthenticator();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "MFA assurance note (method + AAL)";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Records the MFA method and assurance level (AAL) in the user session (claims: mfa_method, aal) and in the LOGIN event.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name(CFG_METHOD).label("MFA method").type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("totp").helpText("e.g. totp, webauthn").add()
                .property().name(CFG_AAL).label("Assurance level").type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("AAL2").helpText("AAL1, AAL2 or AAL3").add()
                .property().name(CFG_CREDENTIAL_TYPE).label("Only if user has credential type")
                .type(ProviderConfigProperty.STRING_TYPE).helpText("e.g. otp, webauthn, recovery-authn-codes").add()
                .build();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
