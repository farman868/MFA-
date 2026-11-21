#!/bin/bash
# OpenVPN gateway: builds a lab PKI on first start, publishes the CA for clients, then runs the server.
set -euo pipefail
: "${RADIUS_SHARED_SECRET:?RADIUS_SHARED_SECRET must be set}"
PKI_DIR=/etc/openvpn/pki
EASYRSA=/usr/share/easy-rsa/easyrsa
export EASYRSA_BATCH=1 EASYRSA_PKI="$PKI_DIR" EASYRSA_REQ_CN="Enterprise Corp Lab VPN CA" EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1

if [ ! -f "$PKI_DIR/issued/vpn-gateway.crt" ]; then
  echo "[openvpn] initialising lab PKI (EC P-256)"
  "$EASYRSA" init-pki
  "$EASYRSA" build-ca nopass
  "$EASYRSA" build-server-full vpn-gateway nopass
fi

# Share the CA certificate with VPN clients (lab: shared volume; production: MDM / client profile).
mkdir -p /etc/openvpn/client-share
cp "$PKI_DIR/ca.crt" /etc/openvpn/client-share/ca.crt
chmod 0644 /etc/openvpn/client-share/ca.crt

# Secret for the verify script, readable only by the unprivileged OpenVPN user.
umask 077
printf '%s' "$RADIUS_SHARED_SECRET" > /etc/openvpn/radius.secret
chown nobody:nogroup /etc/openvpn/radius.secret

mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

exec openvpn --config /etc/openvpn/server.conf
