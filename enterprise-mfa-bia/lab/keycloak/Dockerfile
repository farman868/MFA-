# ---- Stage 1: compile the custom authenticator SPI (SMS/Email OTP bridge + assurance notes)
FROM maven:3.9-eclipse-temurin-17 AS spi
WORKDIR /src
COPY providers/mfa-bridge-authenticator/pom.xml .
RUN mvn -B -q dependency:go-offline
COPY providers/mfa-bridge-authenticator/src ./src
RUN mvn -B -q package -DskipTests

# ---- Stage 2: optimized Keycloak build with the provider baked in
FROM quay.io/keycloak/keycloak:26.0.7 AS builder
# recovery-codes = backup codes (recovery authentication codes) for users who lose their authenticator
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    KC_FEATURES=recovery-codes
COPY --from=spi /src/target/mfa-bridge-authenticator.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

# ---- Stage 3: runtime
FROM quay.io/keycloak/keycloak:26.0.7
COPY --from=builder /opt/keycloak/ /opt/keycloak/
USER root
RUN mkdir -p /var/log/keycloak && chown -R 1000:0 /var/log/keycloak && chmod 0750 /var/log/keycloak
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
