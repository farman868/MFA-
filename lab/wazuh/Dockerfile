FROM wazuh/wazuh-manager:4.9.2

COPY ossec-localfiles.xml /tmp/ossec-localfiles.xml
COPY keycloak_decoders.xml /var/ossec/etc/decoders/
COPY keycloak_rules.xml /var/ossec/etc/rules/

RUN cat /tmp/ossec-localfiles.xml >> /var/ossec/etc/ossec.conf \
    && rm -f /tmp/ossec-localfiles.xml \
    && chown -R wazuh:wazuh /var/ossec/etc/decoders/keycloak_decoders.xml /var/ossec/etc/rules/keycloak_rules.xml /var/ossec/etc/ossec.conf \
    && chmod 660 /var/ossec/etc/decoders/keycloak_decoders.xml /var/ossec/etc/rules/keycloak_rules.xml
