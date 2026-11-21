#!/bin/bash
# auth-user-pass-verify hook. $1 = temp file: line 1 username, line 2 password.
# The password field carries "password + OTP": either OpenVPN static-challenge format
# (SCRV1:base64(password):base64(otp)) or the password with the 6-digit code appended.
set -uo pipefail
CREDS_FILE="$1"
USERNAME=$(sed -n '1p' "$CREDS_FILE")
PASSWORD=$(sed -n '2p' "$CREDS_FILE")
SECRET=$(cat /etc/openvpn/radius.secret)
RADIUS_SERVER="${RADIUS_SERVER:-freeradius:1812}"

# Reject usernames outside the directory naming convention before they reach RADIUS.
if ! [[ "$USERNAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
  echo "radius-verify: rejected malformed username" >&2
  exit 1
fi

escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

RESULT=$(printf 'User-Name = "%s"\nUser-Password = "%s"\nCalling-Station-Id = "%s"\nNAS-Identifier = "openvpn-gateway"\n' \
  "$(escape "$USERNAME")" "$(escape "$PASSWORD")" "${untrusted_ip:-unknown}" \
  | radclient -t 12 -r 1 "$RADIUS_SERVER" auth "$SECRET" 2>&1)

if grep -q "Access-Accept" <<<"$RESULT"; then
  echo "radius-verify: Access-Accept for $USERNAME from ${untrusted_ip:-unknown}" >&2
  exit 0
fi
echo "radius-verify: Access-Reject for $USERNAME from ${untrusted_ip:-unknown}" >&2
exit 1
