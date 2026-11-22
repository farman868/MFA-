#!/bin/bash
# Automated VPN acceptance test: connect as VPN_USER with password + current TOTP (static-challenge
# SCRV1 format), wait for the tunnel, ping the gateway, then disconnect.
# MODE=bad-otp sends a wrong code and expects the connection to be refused.
set -uo pipefail
: "${VPN_USER:?}" "${VPN_PASSWORD:?}" "${VPN_TOTP_SEED:?}"
MODE="${MODE:-good}"

mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

SEED_B32=$(printf '%s' "$VPN_TOTP_SEED" | base32 | tr -d '=\n')
if [ "$MODE" = "bad-otp" ]; then OTP="000000"; else OTP=$(oathtool --totp -b "$SEED_B32"); fi
umask 077
printf '%s\nSCRV1:%s:%s\n' "$VPN_USER" "$(printf '%s' "$VPN_PASSWORD" | base64 -w0)" "$(printf '%s' "$OTP" | base64 -w0)" > /tmp/auth.txt

openvpn --config /etc/openvpn/client.conf --connect-retry-max 1 > /tmp/ovpn.log 2>&1 &
PID=$!
for _ in $(seq 1 30); do
  if grep -q "Initialization Sequence Completed" /tmp/ovpn.log; then break; fi
  if grep -qE "AUTH_FAILED|Exiting due to fatal error" /tmp/ovpn.log; then break; fi
  sleep 1
done
cat /tmp/ovpn.log

if grep -q "Initialization Sequence Completed" /tmp/ovpn.log; then
  ip -4 addr show tun0 | grep inet
  ping -c 2 -W 2 10.8.0.1 && RC=0 || RC=2
  kill "$PID"; wait "$PID" 2>/dev/null
  [ "$MODE" = "good" ] && { echo "VPN_TEST_RESULT=PASS tunnel established with password+TOTP"; exit $RC; }
  echo "VPN_TEST_RESULT=FAIL tunnel established with a wrong OTP"; exit 1
fi
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
if [ "$MODE" = "bad-otp" ] && grep -q "AUTH_FAILED" /tmp/ovpn.log; then
  echo "VPN_TEST_RESULT=PASS wrong OTP refused (AUTH_FAILED)"; exit 0
fi
echo "VPN_TEST_RESULT=FAIL"; exit 1
