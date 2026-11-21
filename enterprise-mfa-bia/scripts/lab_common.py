"""
lab_common.py - shared helpers for the lab scripts (Python 3.9+, standard library only).

  * environment / docker compose wrappers
  * HTTP helpers, a cookie-aware "browser" that walks Keycloak login pages
  * RFC 6238 TOTP
  * Keycloak Admin REST client and mfa-otp-bridge admin client
  * Mailpit and mock-SMS readers
  * VirtualAuthenticator: a software WebAuthn/FIDO2 authenticator (pure-Python ECDSA P-256 + CBOR) that
    emulates a platform authenticator (fingerprint / face: transport "internal", user-verified) or a
    roaming hardware key (YubiKey-style: transport "usb"), so biometrics and hardware-token sign-ins
    can be exercised automatically. Real devices are tested manually (docs/04_MFA_Configuration_Guides.md).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import http.cookiejar
import json
import re
import secrets
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "lab"
EVIDENCE = ROOT / "docs" / "evidence"
REALM = "enterprise-realm"
KC = "http://localhost:8080"
PORTAL = "http://localhost:5000"
HR_PORTAL = "http://localhost:5001"
BRIDGE = "http://localhost:8000"
MAILPIT = "http://localhost:8025"
LDAP_BASE = "dc=corp,dc=enterprise,dc=local"
LAB_USER_PASSWORD = "Corp!Lab2026"  # directory test users - LAB ONLY

# ---------------------------------------------------------------------------------------------- env


def load_env() -> dict[str, str]:
    path = LAB / ".env"
    if not path.exists():
        sys.exit("lab/.env not found - run scripts/setup_lab.sh first")
    env = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def compose(*args: str, input_text: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "--project-directory", str(LAB), "-f", str(LAB / "docker-compose.yml"), *args]
    return subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=timeout)


def utc_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


# --------------------------------------------------------------------------------------------- HTTP


def http_json(url: str, data: dict | None = None, headers: dict | None = None, method: str | None = None,
              form: bool = False):
    if data is not None and form:
        body = urllib.parse.urlencode(data).encode()
        ctype = "application/x-www-form-urlencoded"
    else:
        body = json.dumps(data).encode() if data is not None else None
        ctype = "application/json"
    req = urllib.request.Request(url, data=body, method=method or ("POST" if body is not None else "GET"),
                                 headers={"Content-Type": ctype, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw[:500]}


# --------------------------------------------------------------------------------------------- TOTP

_last_totp_step = {"step": -1}


def totp(seed: str, digits: int = 6, period: int = 30, fresh: bool = True) -> str:
    """RFC 6238 (HMAC-SHA1). Keycloak keys the HMAC with the raw seed bytes. fresh=True waits for a time
    step not used before, because the realm forbids code reuse."""
    step = int(time.time()) // period
    if fresh and step <= _last_totp_step["step"]:
        wait = period - (int(time.time()) % period) + 1
        print(f"        waiting {wait}s for a fresh TOTP window (codes are single-use)")
        time.sleep(wait)
        step = int(time.time()) // period
    _last_totp_step["step"] = step
    mac = hmac.new(seed.encode(), struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


# ------------------------------------------------------------------------------------------ browser


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"id": a.get("id", ""), "action": html.unescape(a.get("action") or ""), "fields": {}}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None and a.get("name"):
            if a.get("type") not in ("submit", "button", "checkbox", "radio") or "checked" in a:
                self._cur["fields"][a["name"]] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


class _LocalhostPolicy(http.cookiejar.DefaultCookiePolicy):
    def return_ok_secure(self, cookie, request):  # the lab is served over http://localhost
        return True


class Browser:
    """Minimal cookie-aware client able to walk Keycloak's server-rendered login pages."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar(policy=_LocalhostPolicy())
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.url, self.body, self.status = "", "", 0

    def get(self, url: str) -> "Browser":
        return self._go(urllib.request.Request(url))

    def post(self, url: str, fields: dict) -> "Browser":
        return self._go(urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST"))

    def _go(self, req) -> "Browser":
        try:
            with self.opener.open(req, timeout=25) as r:
                self.url, self.body, self.status = r.geturl(), r.read().decode(errors="replace"), r.status
        except urllib.error.HTTPError as e:
            self.url, self.body, self.status = e.geturl(), e.read().decode(errors="replace"), e.code
        return self

    def forms(self) -> list[dict]:
        p = _Forms()
        p.feed(self.body)
        return p.forms

    def has_form(self, form_id: str) -> bool:
        return any(f["id"] == form_id for f in self.forms())

    def form(self, form_id: str | None = None, action_contains: str = "login-actions") -> dict:
        forms = self.forms()
        for f in forms:
            if (form_id and f["id"] == form_id) or (
                    not form_id and action_contains in f["action"] and "tryAnotherWay" not in f["fields"]):
                return f
        raise RuntimeError(f"form {form_id or action_contains!r} not found at {self.url} "
                           f"(page message: {self.message() or '-'}; forms: {[f['id'] or f['action'][:50] for f in forms]})")

    def submit(self, form: dict, **values) -> "Browser":
        return self.post(form["action"], {**form["fields"], **values})

    def message(self) -> str:
        """Keycloak / portal feedback text (errors, warnings), if any."""
        for pat in (r'kc-feedback-text[^>]*>(.*?)</', r'id="input-error[^"]*"[^>]*>(.*?)</', r'role="alert"[^>]*>(.*?)</p>',
                    r'class="[^"]*pf-v5-c-alert__title[^"]*"[^>]*>(.*?)</', r'<title>(.*?)</title>'):
            m = re.search(pat, self.body, re.S)
            if m:
                return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", m.group(1)))).strip()
        return ""


def portal_session_fields(body: str) -> dict:
    text = re.sub(r"<[^>]+>", " ", body)
    aal = re.search(r"\b(AAL[123])\b", text)
    method = re.search(r"<code>(webauthn|totp|sms-otp|email-otp|recovery-code|none)</code>", body)
    return {"aal": aal.group(1) if aal else None, "mfa_method": method.group(1) if method else None}


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


# ------------------------------------------------------------------------------ OTP delivery readers


def mailpit_code(to: str, since: float, timeout: int = 15) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s, res = http_json(f"{MAILPIT}/api/v1/search?" + urllib.parse.urlencode({"query": f"to:{to}", "limit": 1}))
        msgs = res.get("messages", []) if s == 200 else []
        if msgs:
            created = datetime.fromisoformat(msgs[0]["Created"].replace("Z", "+00:00")).timestamp()
            if created >= since - 2:
                _, msg = http_json(f"{MAILPIT}/api/v1/message/{msgs[0]['ID']}")
                m = re.search(r"code is: (\d{6})", msg.get("Text", ""))
                if m:
                    return m.group(1)
        time.sleep(1)
    return None


def sms_snapshot(to: str) -> set[str]:
    _, items = http_json(f"{BRIDGE}/sms/outbox?to={urllib.parse.quote(to)}&limit=50")
    return {m["sent_at"] + m["body"] for m in (items if isinstance(items, list) else [])}


def sms_code(to: str, before: set[str], timeout: int = 15) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, items = http_json(f"{BRIDGE}/sms/outbox?to={urllib.parse.quote(to)}&limit=5")
        for m in items if isinstance(items, list) else []:
            if m["sent_at"] + m["body"] not in before:
                return re.search(r"code: (\d{6})", m["body"]).group(1)
        time.sleep(1)
    return None


# ------------------------------------------------------------------------------------ admin clients


class KCAdmin:
    """Keycloak Admin REST API as the bootstrap admin (master realm, admin-cli)."""

    def __init__(self, env: dict[str, str]):
        self.env = env
        self._token, self._exp = "", 0.0

    def token(self) -> str:
        if time.time() > self._exp - 10:
            s, t = http_json(f"{KC}/realms/master/protocol/openid-connect/token", form=True, data={
                "grant_type": "password", "client_id": "admin-cli",
                "username": self.env.get("KC_ADMIN_USER", "kcadmin"), "password": self.env["KC_ADMIN_PASSWORD"]})
            if s != 200:
                raise RuntimeError(f"admin login failed: HTTP {s} {t}")
            self._token, self._exp = t["access_token"], time.time() + t.get("expires_in", 60)
        return self._token

    def call(self, method: str, path: str, data=None):
        return http_json(f"{KC}/admin/realms/{REALM}{path}", data=data, method=method,
                         headers={"Authorization": f"Bearer {self.token()}"})

    def user(self, username: str) -> dict:
        s, users = self.call("GET", f"/users?username={urllib.parse.quote(username)}&exact=true")
        if s != 200 or not users:
            raise RuntimeError(f"user {username} not found (HTTP {s})")
        return users[0]

    def credentials(self, user_id: str) -> list[dict]:
        return self.call("GET", f"/users/{user_id}/credentials")[1]

    def sessions(self, user_id: str) -> list[dict]:
        return self.call("GET", f"/users/{user_id}/sessions")[1]


class BridgeAdmin:
    def __init__(self, env: dict[str, str]):
        self.h = {"X-Bridge-Key": env["BRIDGE_API_KEY"]}

    def post(self, path: str, **data):
        return http_json(f"{BRIDGE}{path}", data, self.h)

    def status(self, username: str):
        return http_json(f"{BRIDGE}/admin/status/{urllib.parse.quote(username)}", headers=self.h)[1]


# ------------------------------------------------------------------- WebAuthn: ECDSA P-256 (pure Python)

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + _A) * pow(2 * p1[1], -1, _P) % _P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, _P) % _P
    x = (lam * lam - p1[0] - p2[0]) % _P
    return x, (lam * (p1[0] - x) - p1[1]) % _P


def _mul(k: int, point):
    result, addend = None, point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def ecdsa_sign(d: int, msg: bytes) -> bytes:
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    while True:
        k = secrets.randbelow(_N - 1) + 1
        r = _mul(k, _G)[0] % _N
        s = pow(k, -1, _N) * (z + r * d) % _N
        if r and s:
            break

    def der_int(v: int) -> bytes:
        b = v.to_bytes((v.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def ecdsa_verify(q, msg: bytes, sig: bytes) -> bool:
    rl = sig[3]
    r = int.from_bytes(sig[4:4 + rl], "big")
    s = int.from_bytes(sig[6 + rl:], "big")
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _N)
    pt = _add(_mul(z * w % _N, _G), _mul(r * w % _N, q))
    return pt is not None and pt[0] % _N == r


# ----------------------------------------------------------------------------- WebAuthn: CBOR + data


def cbor(obj) -> bytes:
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
        raise ValueError("integer too large")
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return head(0, obj) if obj >= 0 else head(1, -1 - obj)
    if isinstance(obj, bytes):
        return head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode()
        return head(3, len(b)) + b
    if isinstance(obj, list):
        return head(4, len(obj)) + b"".join(cbor(x) for x in obj)
    if isinstance(obj, dict):
        return head(5, len(obj)) + b"".join(cbor(k) + cbor(v) for k, v in obj.items())
    raise TypeError(type(obj))


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _page_value(body: str, name: str) -> str | None:
    m = re.search(rf"\b{name}\s*[:=]\s*['\"]([^'\"]*)['\"]", body)
    return m.group(1) if m else None


class VirtualAuthenticator:
    """Software FIDO2 authenticator. kind="platform" emulates fingerprint/face (Windows Hello, Touch ID):
    transport "internal", user verification performed. kind="roaming" emulates a YubiKey: transport "usb",
    user presence (touch) + PIN verification. Attestation format "none"."""

    FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40

    def __init__(self, kind: str, origin: str = KC):
        assert kind in ("platform", "roaming")
        self.kind, self.origin = kind, origin
        self.label = "lab-virtual-platform-biometric" if kind == "platform" else "lab-virtual-yubikey"
        self.transport = "internal" if kind == "platform" else "usb"
        self.d = secrets.randbelow(_N - 1) + 1
        self.q = _mul(self.d, _G)
        self.cred_id = secrets.token_bytes(32)
        self.user_handle = b""
        self.counter = 0

    def _rp_hash(self, body: str) -> bytes:
        rp_id = _page_value(body, "rpId") or urllib.parse.urlparse(self.origin).hostname
        return hashlib.sha256(rp_id.encode()).digest()

    def _client_data(self, typ: str, challenge: str) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge, "origin": self.origin, "crossOrigin": False},
                          separators=(",", ":")).encode()

    def register(self, body: str) -> dict:
        challenge = _page_value(body, "challenge")
        userid = _page_value(body, "userid")
        if not challenge:
            raise RuntimeError("WebAuthn registration challenge not found on page")
        self.user_handle = b64u_dec(userid) if userid else b""
        self.counter += 1
        cose = cbor({1: 2, 3: -7, -1: 1, -2: self.q[0].to_bytes(32, "big"), -3: self.q[1].to_bytes(32, "big")})
        attested = bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + cose
        auth_data = (self._rp_hash(body) + bytes([self.FLAG_UP | self.FLAG_UV | self.FLAG_AT])
                     + struct.pack(">I", self.counter) + attested)
        return {"clientDataJSON": b64u(self._client_data("webauthn.create", challenge)),
                "attestationObject": b64u(cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})),
                "publicKeyCredentialId": b64u(self.cred_id), "authenticatorLabel": self.label,
                "transports": self.transport, "error": ""}

    def assertion(self, body: str) -> dict:
        challenge = _page_value(body, "challenge")
        if not challenge:
            raise RuntimeError("WebAuthn authentication challenge not found on page")
        self.counter += 1
        auth_data = self._rp_hash(body) + bytes([self.FLAG_UP | self.FLAG_UV]) + struct.pack(">I", self.counter)
        client_data = self._client_data("webauthn.get", challenge)
        sig = ecdsa_sign(self.d, auth_data + hashlib.sha256(client_data).digest())
        return {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
                "signature": b64u(sig), "credentialId": b64u(self.cred_id),
                "userHandle": b64u(self.user_handle), "error": ""}


# ------------------------------------------------------------------------------------- log helpers


def read_container_file(path: str, lines: int = 5000) -> str:
    return compose("exec", "-T", "wazuh-manager", "tail", "-n", str(lines), path).stdout


def lines_since(text: str, since_utc: str) -> list[str]:
    """Keycloak/bridge lines start with 'YYYY-MM-DD HH:MM:SS' (container clock, UTC)."""
    return [ln for ln in text.splitlines() if ln[:19] >= since_utc and re.match(r"\d{4}-\d\d-\d\d \d\d:", ln)]


def alerts_since(since_iso: str, max_lines: int = 20000) -> list[dict]:
    raw = compose("exec", "-T", "wazuh-manager", "tail", "-n", str(max_lines),
                  "/var/ossec/logs/alerts/alerts.json").stdout
    out = []
    for ln in raw.splitlines():
        try:
            a = json.loads(ln)
        except ValueError:
            continue
        if str(a.get("rule", {}).get("id", "")).startswith("1005") and a.get("timestamp", "")[:19] >= since_iso:
            out.append(a)
    return out


def alert_user(alert: dict) -> str:
    data = alert.get("data", {})
    return (data.get("keycloak", {}) or {}).get("username") or data.get("dstuser", "")


def logtest(lines: list[str]) -> str:
    r = compose("exec", "-T", "wazuh-manager", "/var/ossec/bin/wazuh-logtest",
                input_text="\n".join(lines) + "\n", timeout=240)
    return r.stdout + r.stderr
