#!/usr/bin/env bash
# Fast checks that need no running lab (also usable locally): Python, shell, XML, JSON, compose, LF endings.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
fail=0
step() { printf '\n== %s\n' "$*"; }

step "Python: compile + ruff"
python3 -m py_compile scripts/*.py scripts/ci/*.py lab/mfa-otp-bridge/app/main.py lab/corp-portal/app.py
if command -v ruff >/dev/null; then ruff check --select E,F,W,B --line-length 130 scripts lab || fail=1; fi

step "Python: crypto / CBOR / WebAuthn emulator self-test"
python3 - <<'PY'
import hashlib, sys
sys.path.insert(0, "scripts")
import lab_common as c
d = 0x1234567890ABCDEF
q = c._mul(d, c._G)
sig = c.ecdsa_sign(d, b"ci")
assert c.ecdsa_verify(q, b"ci", sig) and not c.ecdsa_verify(q, b"x", sig)
assert c.cbor({1: 2, 3: 4}) == bytes.fromhex("a201020304") and c.cbor(-7) == b"\x26"
va = c.VirtualAuthenticator("roaming")
va.register("challenge : 'abc', userid : 'dXNlcg', rpId : 'localhost'")
a = va.assertion("challenge : 'def', rpId : 'localhost'")
ad, cd = c.b64u_dec(a["authenticatorData"]), c.b64u_dec(a["clientDataJSON"])
assert c.ecdsa_verify(va.q, ad + hashlib.sha256(cd).digest(), c.b64u_dec(a["signature"]))
print("self-test OK")
PY

step "Shell: syntax + shellcheck (errors only)"
for f in scripts/*.sh scripts/ci/*.sh lab/*/entrypoint.sh lab/openvpn/radius-verify.sh; do bash -n "$f" || fail=1; done
if command -v shellcheck >/dev/null; then
  shellcheck -S error scripts/*.sh scripts/ci/*.sh lab/*/entrypoint.sh lab/openvpn/radius-verify.sh || fail=1
fi

step "XML (Wazuh decoders/rules, ossec snippet, pom) + realm JSON"
python3 - <<'PY'
import json, xml.etree.ElementTree as ET
for f in ["siem/keycloak_decoders.xml", "siem/keycloak_rules.xml", "lab/wazuh/ossec-localfiles.xml"]:
    ET.fromstring("<root>" + open(f).read() + "</root>")  # Wazuh files have several top-level elements
ET.parse("lab/keycloak/providers/mfa-bridge-authenticator/pom.xml")
realm = json.load(open("lab/keycloak/realm/enterprise-realm.json"))
aliases = {c["alias"] for c in realm["authenticatorConfig"]}
flows = {f["alias"] for f in realm["authenticationFlows"]}
for f in realm["authenticationFlows"]:
    for e in f["authenticationExecutions"]:
        assert e.get("authenticatorConfig") in (None, *aliases), e
        assert not e["authenticatorFlow"] or e["flowAlias"] in flows, e
print("XML and realm JSON OK")
PY

step "docker compose config"
cp lab/.env.example lab/.env.ci-check
docker compose --project-directory lab -f lab/docker-compose.yml --env-file lab/.env.ci-check --profile vpn-test config -q || fail=1
rm -f lab/.env.ci-check

step "Line endings (scripts must be LF)"
if grep -rlI $'\r' scripts lab --include=*.sh --include=*.py --include=*.conf --include=rest --include=mfa-site; then
  echo "CRLF line endings found in the files above"; fail=1
fi

exit $fail
