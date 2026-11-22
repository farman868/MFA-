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

public class BridgeOtpAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "bridge-otp-authenticator";
    public static final String CFG_BRIDGE_URL = "bridge.url";
    public static final String CFG_PURPOSE = "purpose";

    private static final BridgeOtpAuthenticator SINGLETON = new BridgeOtpAuthenticator();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "SMS / Email OTP (mfa-otp-bridge)";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
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
        return "Sends a time-bound one-time code by SMS or email through the mfa-otp-bridge service and verifies it. "
                + "Intended for onboarding and accessibility fallback, not for privileged users.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(CFG_BRIDGE_URL)
                .label("Bridge base URL")
                .helpText("Base URL of the mfa-otp-bridge service. Falls back to the MFA_BRIDGE_URL environment variable.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("http://mfa-otp-bridge:8000")
                .add()
                .property()
                .name(CFG_PURPOSE)
                .label("Purpose")
                .helpText("signin = fallback second factor; enrolment = initial verification before a user registers an authenticator")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options("signin", "enrolment")
                .defaultValue("signin")
                .add()
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
