FROM wazuh/wazuh-manager:4.9.2

COPY ossec-localfiles.xml /tmp/ossec-localfiles.xml
COPY keycloak_decoders.xml /tmp/keycloak_decoders.xml
COPY keycloak_rules.xml /tmp/keycloak_rules.xml

RUN mkdir -p /var/ossec/data_tmp/permanent/var/ossec/etc/decoders \
             /var/ossec/data_tmp/permanent/var/ossec/etc/rules \
    && cp /tmp/keycloak_decoders.xml /var/ossec/data_tmp/permanent/var/ossec/etc/decoders/keycloak_decoders.xml \
    && cp /tmp/keycloak_rules.xml /var/ossec/data_tmp/permanent/var/ossec/etc/rules/keycloak_rules.xml \
    && cat /tmp/ossec-localfiles.xml >> /var/ossec/data_tmp/permanent/var/ossec/etc/ossec.conf \
    && rm -f /tmp/ossec-localfiles.xml /tmp/keycloak_decoders.xml /tmp/keycloak_rules.xml \
    && chown -R wazuh:wazuh /var/ossec/data_tmp/permanent/var/ossec/etc/ \
    && chmod -R 770 /var/ossec/data_tmp/permanent/var/ossec/etc/ \
    && rm -rf /var/ossec/etc
