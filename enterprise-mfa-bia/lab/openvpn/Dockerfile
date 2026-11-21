FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openvpn easy-rsa freeradius-utils iproute2 iputils-ping ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY server.conf /etc/openvpn/server.conf
COPY radius-verify.sh /etc/openvpn/radius-verify.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /etc/openvpn/radius-verify.sh /usr/local/bin/entrypoint.sh
EXPOSE 1194/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
