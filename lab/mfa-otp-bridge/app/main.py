"""
mfa-otp-bridge - SMS / Email OTP service and RADIUS-to-Keycloak adapter for the enterprise MFA lab.

Responsibilities
  1. /otp/send, /otp/verify  - called by the Keycloak "bridge-otp-authenticator" SPI.
     Generates 6-digit, time-bound OTPs, delivers them by email (SMTP -> Mailpit) or a MOCK SMS
     gateway, stores only an HMAC of each code, enforces TTL, attempt limits and send-rate limits.
  2. /radius/authenticate    - called by FreeRADIUS (rlm_rest). Splits "password + OTP", validates
     both against Keycloak (direct grant, client vpn-radius), and authorizes on the vpn-users role.
  3. Security event log      - Keycloak-compatible key="value" lines tagged [mfa-otp-bridge],
     parsed by the same Wazuh decoder as Keycloak's own [org.keycloak.events] lines.

LAB ONLY: the SMS gateway is a mock. /sms/outbox and /sms/inbox act as the user's "phone".
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import smtplib
import socket
import threading
import time
from collections import defaultdict, deque
from email.message import EmailMessage
from typing import Any

import requests
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- configuration


def env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"missing required environment variable {name}")
    return value


BRIDGE_API_KEY = env("BRIDGE_API_KEY")
OTP_HMAC_KEY = env("OTP_HMAC_KEY").encode()
OTP_TTL = int(env("OTP_TTL_SECONDS", "300"))
OTP_MAX_ATTEMPTS = int(env("OTP_MAX_ATTEMPTS", "5"))
SEND_LIMIT_PER_MINUTE = int(env("OTP_SEND_LIMIT_PER_MINUTE", "3"))
SEND_LIMIT_PER_HOUR = int(env("OTP_SEND_LIMIT_PER_HOUR", "10"))
SMTP_HOST = env("SMTP_HOST", "mailpit")
SMTP_PORT = int(env("SMTP_PORT", "1025"))
MAIL_FROM = env("MAIL_FROM", "iam-noreply@corp.enterprise.local")
KC_TOKEN_URL = env("KEYCLOAK_TOKEN_URL", "http://keycloak:8080/realms/enterprise-realm/protocol/openid-connect/token")
KC_LOGOUT_URL = env("KEYCLOAK_LOGOUT_URL", "http://keycloak:8080/realms/enterprise-realm/protocol/openid-connect/logout")
VPN_CLIENT_ID = env("VPN_CLIENT_ID", "vpn-radius")
VPN_CLIENT_SECRET = env("VPN_CLIENT_SECRET")
VPN_REQUIRED_ROLE = env("VPN_REQUIRED_ROLE", "vpn-users")
RADIUS_ALLOWED_HOSTS = [h.strip() for h in env("RADIUS_ALLOWED_HOSTS", "freeradius").split(",") if h.strip()]
SMS_OUTBOX_ENABLED = env("SMS_OUTBOX_ENABLED", "true").lower() == "true"
EVENT_LOG = env("EVENT_LOG", "/var/log/mfa/bridge-events.log")
REALM = env("REALM", "enterprise-realm")

# --------------------------------------------------------------------------- security event log

os.makedirs(os.path.dirname(EVENT_LOG), exist_ok=True)
_events = logging.getLogger("mfa-otp-bridge.events")
_events.setLevel(logging.INFO)
_events.propagate = False
_fmt = logging.Formatter("%(asctime)s,%(msecs)03d %(levelname)-5s [mfa-otp-bridge] (%(threadName)s) %(message)s",
                         datefmt="%Y-%m-%d %H:%M:%S")
for _h in (logging.FileHandler(EVENT_LOG), logging.StreamHandler()):
    _h.setFormatter(_fmt)
    _events.addHandler(_h)

_SAFE = re.compile(r'["\\\r\n]')


def security_event(event_type: str, *, username: str = "", ip: str = "", client_id: str = "mfa-otp-bridge",
                   error: str | None = None, **details: Any) -> None:
    """Emit one event in Keycloak's jboss-logging key="value" layout (never includes OTP values)."""
    fields: dict[str, Any] = {"type": event_type, "realmId": REALM, "clientId": client_id, "userId": "",
                              "ipAddress": ip or "unknown"}
    if error:
        fields["error"] = error
    fields["username"] = username
    fields.update(details)
    line = ", ".join(f'{k}="{_SAFE.sub("_", str(v))}"' for k, v in fields.items())
    (_events.warning if error else _events.info)(line)


# --------------------------------------------------------------------------- OTP state (in memory)

_lock = threading.Lock()
_challenges: dict[str, dict[str, Any]] = {}
_send_history: dict[str, deque[float]] = defaultdict(deque)
_sms_outbox: deque[dict[str, Any]] = deque(maxlen=200)
_locked_users: set[str] = set()  # IR containment: OTP channel disabled for these accounts


def _digest(challenge_id: str, code: str) -> str:
    return hmac.new(OTP_HMAC_KEY, f"{challenge_id}:{code}".encode(), hashlib.sha256).hexdigest()


def _rate_limited(username: str) -> bool:
    now = time.time()
    with _lock:
        hist = _send_history[username]
        while hist and now - hist[0] > 3600:
            hist.popleft()
        last_minute = sum(1 for t in hist if now - t <= 60)
        if last_minute >= SEND_LIMIT_PER_MINUTE or len(hist) >= SEND_LIMIT_PER_HOUR:
            return True
        hist.append(now)
        return False


def _purge_expired() -> None:
    now = time.time()
    with _lock:
        for cid in [c for c, v in _challenges.items() if v["expires"] < now]:
            del _challenges[cid]


def mask(destination: str, channel: str) -> str:
    if channel == "email" and "@" in destination:
        local, domain = destination.split("@", 1)
        return f"{local[:1]}***@{domain}"
    return "*******" + destination[-3:]


def require_key(key: str | None) -> None:
    if not key or not hmac.compare_digest(key, BRIDGE_API_KEY):
        raise HTTPException(status_code=401, detail="invalid bridge key")


# --------------------------------------------------------------------------- delivery channels


def deliver_email(to: str, code: str, username: str) -> None:
    msg = EmailMessage()
    msg["From"] = f"Enterprise Corp IAM <{MAIL_FROM}>"
    msg["To"] = to
    msg["Subject"] = "Your Enterprise Corp sign-in code"
    msg.set_content(
        f"Hello {username},\n\n"
        f"Your sign-in verification code is: {code}\n\n"
        f"It expires in {OTP_TTL // 60} minutes and can be used once.\n"
        "IT will never ask you for this code. If you did not try to sign in, do not share it and "
        "report this email to the IT service desk immediately.\n"
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as smtp:
        smtp.send_message(msg)


def deliver_sms(to: str, code: str) -> None:
    # MOCK gateway: production would call a carrier/SMS API here (Twilio, AWS SNS, etc.).
    _sms_outbox.appendleft({
        "to": to,
        "body": f"Enterprise Corp code: {code}. Expires in {OTP_TTL // 60} min. Never share it. Not you? Call IT.",
        "sent_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    })


# --------------------------------------------------------------------------- API

app = FastAPI(title="mfa-otp-bridge", version="1.0.0", docs_url="/docs", redoc_url=None)


class SendRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    user_id: str = ""
    realm: str = REALM
    client_id: str = ""
    channel: str = Field(pattern="^(sms|email)$")
    destination: str = Field(min_length=3, max_length=254)
    ip_address: str = ""


class VerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=8, max_length=64)
    code: str = Field(max_length=16)
    username: str = ""
    ip_address: str = ""


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "UP", "active_challenges": len(_challenges)}


@app.post("/otp/send")
def otp_send(req: SendRequest, x_bridge_key: str | None = Header(default=None)) -> JSONResponse:
    require_key(x_bridge_key)
    _purge_expired()
    method = f"{req.channel}-otp"
    if req.username in _locked_users:
        security_event("SEND_OTP", username=req.username, ip=req.ip_address, client_id=req.client_id or "unknown",
                       error="account_locked", mfa_method=method, channel=req.channel)
        return JSONResponse(status_code=423, content={"error": "account_locked"})
    if _rate_limited(req.username):
        security_event("SEND_OTP", username=req.username, ip=req.ip_address, client_id=req.client_id or "unknown",
                       error="rate_limited", mfa_method=method, channel=req.channel)
        return JSONResponse(status_code=429, content={"error": "rate_limited", "retry_after": 60})

    code = f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = secrets.token_urlsafe(18)
    try:
        if req.channel == "email":
            deliver_email(req.destination, code, req.username)
        else:
            deliver_sms(req.destination, code)
    except (OSError, smtplib.SMTPException) as exc:
        security_event("SEND_OTP", username=req.username, ip=req.ip_address, client_id=req.client_id or "unknown",
                       error="delivery_failed", mfa_method=method, channel=req.channel, detail=type(exc).__name__)
        return JSONResponse(status_code=502, content={"error": "delivery_failed"})

    with _lock:
        _challenges[challenge_id] = {
            "digest": _digest(challenge_id, code), "username": req.username, "channel": req.channel,
            "expires": time.time() + OTP_TTL, "attempts": 0,
        }
    security_event("SEND_OTP", username=req.username, ip=req.ip_address, client_id=req.client_id or "unknown",
                   mfa_method=method, channel=req.channel, destination=mask(req.destination, req.channel))
    return JSONResponse({"challenge_id": challenge_id, "masked_destination": mask(req.destination, req.channel),
                         "expires_in": OTP_TTL})


@app.post("/otp/verify")
def otp_verify(req: VerifyRequest, x_bridge_key: str | None = Header(default=None)) -> JSONResponse:
    require_key(x_bridge_key)
    code = re.sub(r"\s", "", req.code)
    with _lock:
        ch = _challenges.get(req.challenge_id)
        if ch is None or ch["expires"] < time.time():
            _challenges.pop(req.challenge_id, None)
            result, status = {"valid": False, "error": "expired_code"}, 400
            username, method = req.username, "otp"
        elif ch["attempts"] >= OTP_MAX_ATTEMPTS:
            del _challenges[req.challenge_id]
            result, status = {"valid": False, "error": "too_many_attempts"}, 400
            username, method = ch["username"], f"{ch['channel']}-otp"
        else:
            username, method = ch["username"], f"{ch['channel']}-otp"
            if hmac.compare_digest(ch["digest"], _digest(req.challenge_id, code)):
                del _challenges[req.challenge_id]
                result, status = {"valid": True}, 200
            else:
                ch["attempts"] += 1
                result = {"valid": False, "error": "invalid_otp",
                          "attempts_remaining": OTP_MAX_ATTEMPTS - ch["attempts"]}
                status = 401
    if result["valid"]:
        security_event("OTP_VERIFIED", username=username, ip=req.ip_address, mfa_method=method)
    else:
        security_event("OTP_VERIFY_ERROR", username=username, ip=req.ip_address, error=result["error"],
                       mfa_method=method)
    return JSONResponse(status_code=status, content=result)


class ThrottleResetRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    operator: str = Field(default="unknown", max_length=128)
    reason: str = Field(default="", max_length=256)


@app.post("/admin/throttle/reset")
def throttle_reset(req: ThrottleResetRequest, x_bridge_key: str | None = Header(default=None)) -> dict[str, Any]:
    """IR recovery / test hygiene: clear send-rate counters and pending challenges for one user."""
    require_key(x_bridge_key)
    with _lock:
        _send_history.pop(req.username, None)
        stale = [c for c, v in _challenges.items() if v["username"] == req.username]
        for c in stale:
            del _challenges[c]
    security_event("OTP_THROTTLE_RESET", username=req.username, client_id="mfa-otp-bridge-admin",
                   operator=req.operator, reason=req.reason, revoked_challenges=len(stale))
    return {"username": req.username, "revoked_challenges": len(stale)}


class LockRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    operator: str = Field(default="unknown", max_length=128)
    reason: str = Field(default="", max_length=256)


@app.post("/admin/lock")
def lock_user(req: LockRequest, x_bridge_key: str | None = Header(default=None)) -> dict[str, Any]:
    """IR containment: stop issuing OTPs for an account and void its pending challenges."""
    require_key(x_bridge_key)
    with _lock:
        _locked_users.add(req.username)
        stale = [c for c, v in _challenges.items() if v["username"] == req.username]
        for c in stale:
            del _challenges[c]
    security_event("OTP_CHANNEL_LOCKED", username=req.username, client_id="mfa-otp-bridge-admin",
                   operator=req.operator, reason=req.reason, revoked_challenges=len(stale))
    return {"username": req.username, "locked": True, "revoked_challenges": len(stale)}


@app.post("/admin/unlock")
def unlock_user(req: LockRequest, x_bridge_key: str | None = Header(default=None)) -> dict[str, Any]:
    """IR recovery: re-enable OTP issuance and clear rate-limit counters."""
    require_key(x_bridge_key)
    with _lock:
        _locked_users.discard(req.username)
        _send_history.pop(req.username, None)
    security_event("OTP_CHANNEL_UNLOCKED", username=req.username, client_id="mfa-otp-bridge-admin",
                   operator=req.operator, reason=req.reason)
    return {"username": req.username, "locked": False}


@app.get("/admin/status/{username}")
def user_status(username: str, x_bridge_key: str | None = Header(default=None)) -> dict[str, Any]:
    require_key(x_bridge_key)
    now = time.time()
    with _lock:
        sends = [t for t in _send_history.get(username, ()) if now - t <= 3600]
        pending = sum(1 for v in _challenges.values() if v["username"] == username)
    return {"username": username, "locked": username in _locked_users, "sends_last_hour": len(sends),
            "pending_challenges": pending}


# --------------------------------------------------------------------------- mock SMS handset (LAB ONLY)


@app.get("/sms/outbox")
def sms_outbox(to: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
    if not SMS_OUTBOX_ENABLED:
        raise HTTPException(status_code=404)
    items = [m for m in _sms_outbox if to is None or m["to"] == to]
    return items[: max(1, min(limit, 50))]


@app.get("/sms/inbox", response_class=HTMLResponse)
def sms_inbox() -> str:
    if not SMS_OUTBOX_ENABLED:
        raise HTTPException(status_code=404)
    rows = "".join(
        f"<li><strong>{html.escape(m['to'])}</strong> <time>{html.escape(m['sent_at'])}</time>"
        f"<p>{html.escape(m['body'])}</p></li>" for m in _sms_outbox
    ) or "<li>No messages yet.</li>"
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta http-equiv='refresh' content='5'>"
        "<title>Mock SMS handset</title><style>body{font:16px/1.5 system-ui;max-width:42rem;margin:2rem auto;"
        "padding:0 1rem}li{border:1px solid #888;border-radius:8px;padding:.5rem 1rem;margin:.5rem 0;"
        "list-style:none}time{color:#555;margin-left:.5rem}</style></head><body>"
        "<h1>Mock SMS handset (lab only)</h1><p>Messages sent by the mfa-otp-bridge mock SMS gateway. "
        "Refreshes every 5 seconds.</p><ul aria-live='polite'>" + rows + "</ul></body></html>"
    )


# --------------------------------------------------------------------------- RADIUS adapter


def _radius_source_allowed(peer: str) -> bool:
    allowed: set[str] = set()
    for host in RADIUS_ALLOWED_HOSTS:
        try:
            allowed.update(info[4][0] for info in socket.getaddrinfo(host, None))
        except socket.gaierror:
            continue
    return peer in allowed


def _attr(body: dict[str, Any], name: str) -> str:
    """rlm_rest JSON encodes attributes as {"Name": {"type": "...", "value": ["..."]}}."""
    v = body.get(name)
    if isinstance(v, dict):
        v = v.get("value")
    if isinstance(v, list):
        v = v[0] if v else ""
    return "" if v is None else str(v)


def split_password_and_otp(raw: str) -> tuple[str, str]:
    """Supports OpenVPN static-challenge (SCRV1:b64(password):b64(otp)) and 'password' + 6 trailing digits."""
    if raw.startswith("SCRV1:"):
        try:
            _, b64pass, b64otp = raw.split(":", 2)
            return base64.b64decode(b64pass).decode(), base64.b64decode(b64otp).decode().strip()
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return raw, ""
    m = re.fullmatch(r"(?s)(.+?)(\d{6})", raw)
    return (m.group(1), m.group(2)) if m else (raw, "")


def _jwt_claims(token: str) -> dict[str, Any]:
    # Token was obtained by us directly from Keycloak over the backchannel; payload decode only.
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


@app.post("/radius/authenticate")
async def radius_authenticate(request: Request) -> Response:
    peer = request.client.host if request.client else ""
    if not _radius_source_allowed(peer):
        raise HTTPException(status_code=403, detail="RADIUS endpoint accepts requests from FreeRADIUS only")

    try:
        body = await request.json()
    except ValueError:
        body = {}
    username, raw_password = _attr(body, "User-Name"), _attr(body, "User-Password")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            username, raw_password = base64.b64decode(auth[6:]).decode().split(":", 1)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass
    client_ip = _attr(body, "Calling-Station-Id") or _attr(body, "NAS-IP-Address") or peer

    password, otp = split_password_and_otp(raw_password)
    if not username or not password or not otp:
        security_event("RADIUS_AUTH_ERROR", username=username, ip=client_ip, client_id=VPN_CLIENT_ID,
                       error="otp_missing", mfa_method="totp")
        return Response(status_code=401)

    try:
        r = requests.post(KC_TOKEN_URL, timeout=8, data={
            "grant_type": "password", "client_id": VPN_CLIENT_ID, "client_secret": VPN_CLIENT_SECRET,
            "username": username, "password": password, "totp": otp, "scope": "openid",
        })
    except requests.RequestException:
        security_event("RADIUS_AUTH_ERROR", username=username, ip=client_ip, client_id=VPN_CLIENT_ID,
                       error="idp_unreachable", mfa_method="totp")
        return Response(status_code=503)

    if r.status_code != 200:
        desc = ""
        try:
            desc = r.json().get("error_description", "")
        except ValueError:
            pass
        reason = {"Invalid user credentials": "invalid_user_credentials", "Account disabled": "user_disabled",
                  "Account is not fully set up": "mfa_not_enrolled"}.get(desc, "auth_failed")
        security_event("RADIUS_AUTH_ERROR", username=username, ip=client_ip, client_id=VPN_CLIENT_ID,
                       error=reason, mfa_method="totp")
        return Response(status_code=401)

    tokens = r.json()
    roles = _jwt_claims(tokens["access_token"]).get("realm_access", {}).get("roles", [])
    # Single-use session: VPN only needs the decision, so close the Keycloak session immediately.
    try:
        requests.post(KC_LOGOUT_URL, timeout=5, data={"client_id": VPN_CLIENT_ID, "client_secret": VPN_CLIENT_SECRET,
                                                      "refresh_token": tokens.get("refresh_token", "")})
    except requests.RequestException:
        pass

    if VPN_REQUIRED_ROLE not in roles:
        security_event("RADIUS_AUTH_ERROR", username=username, ip=client_ip, client_id=VPN_CLIENT_ID,
                       error="not_authorized_for_vpn", mfa_method="totp")
        return Response(status_code=401)

    security_event("RADIUS_AUTH", username=username, ip=client_ip, client_id=VPN_CLIENT_ID, mfa_method="totp")
    return Response(status_code=204)
