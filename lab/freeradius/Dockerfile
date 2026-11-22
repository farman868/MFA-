FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends freeradius freeradius-rest freeradius-utils \
 && rm -rf /var/lib/apt/lists/*
ENV RADDB=/etc/freeradius/3.0
# Minimal, purpose-built configuration: one virtual server that delegates password+OTP checks
# to the mfa-otp-bridge (which validates against Keycloak). Unused EAP/inner-tunnel config removed.
RUN rm -f $RADDB/sites-enabled/* $RADDB/mods-enabled/eap $RADDB/mods-enabled/rest
COPY raddb/clients.conf $RADDB/clients.conf
COPY raddb/rest $RADDB/mods-available/rest
COPY raddb/mfa-site $RADDB/sites-available/mfa
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN ln -s ../mods-available/rest $RADDB/mods-enabled/rest \
 && ln -s ../sites-available/mfa $RADDB/sites-enabled/mfa \
 && chmod 0755 /usr/local/bin/entrypoint.sh \
 && chown -R freerad:freerad $RADDB
EXPOSE 1812/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
