"""
corp-portal - sample enterprise web application protected by Keycloak OIDC (authorization code + PKCE).

Shows the signed-in user's identity, roles, MFA method and Enterprise Corp assurance level
(AAL1 = single factor or email OTP, AAL2 = TOTP / SMS OTP / backup code, AAL3 = WebAuthn),
and enforces assurance-based authorization on two protected areas:
  /finance  requires AAL2 or higher
  /admin    requires AAL3 (phishing-resistant) AND the it-admins role

/legacy reproduces the PRE-MFA baseline for the assessment: a direct LDAP simple bind over cleartext
ldap://, password only, no lockout and no security logging. It exists only to evidence the gaps.

Front-channel URLs (browser) use KC_PUBLIC_URL (http://localhost:8080); back-channel calls from the
container use KC_INTERNAL_URL (http://keycloak:8080). Keycloak runs with hostname-backchannel-dynamic,
so the token issuer is always the public URL.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from functools import wraps
from urllib.parse import urlencode

import jwt
import requests
from flask import Flask, abort, redirect, render_template, request, session, url_for
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

KC_PUBLIC = os.environ["KC_PUBLIC_URL"].rstrip("/")
KC_INTERNAL = os.environ["KC_INTERNAL_URL"].rstrip("/")
REALM = os.environ.get("KC_REALM", "enterprise-realm")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "corp-portal")
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
APP_URL = os.environ.get("APP_PUBLIC_URL", "http://localhost:5000").rstrip("/")
APP_NAME = os.environ.get("APP_NAME", "Corp Portal")

ISSUER = f"{KC_PUBLIC}/realms/{REALM}"
AUTH_URL = f"{ISSUER}/protocol/openid-connect/auth"
LOGOUT_URL = f"{ISSUER}/protocol/openid-connect/logout"
TOKEN_URL = f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/token"
JWKS_URL = f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/certs"
REDIRECT_URI = f"{APP_URL}/callback"

AAL_RANK = {"AAL1": 1, "AAL2": 2, "AAL3": 3}
METHOD_LABEL = {
    "webauthn": "FIDO2 / WebAuthn (platform biometrics or hardware security key)",
    "totp": "Authenticator app (TOTP)",
    "sms-otp": "SMS one-time code (restricted authenticator)",
    "email-otp": "Email one-time code (fallback only)",
    "recovery-code": "Backup (recovery) code",
}

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
# Cookies are not port-scoped: give each app (corp-portal :5000, hr-portal :5001) its own cookie name.
app.config.update(SESSION_COOKIE_NAME=f"{CLIENT_ID}_session", SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=1800)
_jwks = jwt.PyJWKClient(JWKS_URL, cache_keys=True)


@app.context_processor
def _app_name():
    return {"app_name": APP_NAME}


def _verify(token: str, audience: str | None) -> dict:
    key = _jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["RS256", "ES256", "PS256"], issuer=ISSUER,
                      audience=audience, options={"verify_aud": audience is not None}, leeway=30)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "claims" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def require_assurance(min_aal: str, role: str | None = None):
    def deco(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            c = session["claims"]
            have = AAL_RANK.get(c.get("aal", "AAL1"), 1)
            if have < AAL_RANK[min_aal] or (role and role not in c.get("realm_roles", [])):
                return render_template("denied.html", claims=c, required=min_aal, role=role), 403
            return view(*args, **kwargs)
        return login_required(wrapper)
    return deco


@app.get("/")
def index():
    return render_template("index.html", claims=session.get("claims"))


@app.get("/login")
def login():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    session["oidc"] = {"state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(24),
                       "verifier": verifier, "next": request.args.get("next", "/me")}
    params = {"client_id": CLIENT_ID, "response_type": "code", "scope": "openid profile email",
              "redirect_uri": REDIRECT_URI, "state": session["oidc"]["state"], "nonce": session["oidc"]["nonce"],
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if request.args.get("force"):
        params["prompt"] = "login"
    return redirect(f"{AUTH_URL}?{urlencode(params)}")


@app.get("/callback")
def callback():
    pending = session.pop("oidc", None)
    if not pending or request.args.get("state") != pending["state"]:
        abort(400, "invalid state")
    if "error" in request.args:
        return render_template("error.html", error=request.args.get("error"),
                               description=request.args.get("error_description", "")), 401
    r = requests.post(TOKEN_URL, timeout=10, data={
        "grant_type": "authorization_code", "code": request.args["code"], "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code_verifier": pending["verifier"]})
    if r.status_code != 200:
        return render_template("error.html", error="token_exchange_failed", description=r.text[:300]), 502
    tokens = r.json()
    id_claims = _verify(tokens["id_token"], audience=CLIENT_ID)
    if id_claims.get("nonce") != pending["nonce"]:
        abort(400, "nonce mismatch")
    access = _verify(tokens["access_token"], audience=None)
    session["claims"] = {
        "sub": id_claims["sub"], "username": id_claims.get("preferred_username"),
        "name": id_claims.get("name"), "email": id_claims.get("email"),
        "department": id_claims.get("department", ""),
        "realm_roles": sorted(access.get("realm_access", {}).get("roles", [])),
        "mfa_method": id_claims.get("mfa_method", "none"),
        "mfa_label": METHOD_LABEL.get(id_claims.get("mfa_method", ""), "None (single factor)"),
        "aal": id_claims.get("aal", "AAL1"), "acr": id_claims.get("acr"),
        "auth_time": time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(id_claims.get("auth_time", 0))),
        "session_id": id_claims.get("sid"),
    }
    session["id_token"] = tokens["id_token"]
    return redirect(pending.get("next") or "/me")


@app.get("/me")
@login_required
def me():
    return render_template("me.html", claims=session["claims"])


@app.get("/finance")
@require_assurance("AAL2")
def finance():
    return render_template("area.html", claims=session["claims"], title="Finance approvals",
                           text="Payment approvals require at least AAL2 (authenticator app, SMS OTP or stronger).")


@app.get("/admin")
@require_assurance("AAL3", role="it-admins")
def admin():
    return render_template("area.html", claims=session["claims"], title="IAM administration",
                           text="Privileged administration requires AAL3 phishing-resistant MFA and the it-admins role.")


@app.get("/logout")
def logout():
    id_token = session.get("id_token")
    session.clear()
    params = {"post_logout_redirect_uri": f"{APP_URL}/", "client_id": CLIENT_ID}
    if id_token:
        params["id_token_hint"] = id_token
    return redirect(f"{LOGOUT_URL}?{urlencode(params)}")


# ----------------------------------------------------------------------------- legacy baseline (pre-MFA)
LDAP_URL = os.environ.get("LEGACY_LDAP_URL", "ldap://openldap:389")
LDAP_BASE = os.environ.get("LEGACY_LDAP_BASE", "dc=corp,dc=enterprise,dc=local")
LDAP_RO_DN = os.environ.get("LEGACY_LDAP_BIND_DN", f"cn=readonly,{LDAP_BASE}")
LDAP_RO_PW = os.environ.get("LEGACY_LDAP_BIND_PASSWORD", "")


@app.route("/legacy", methods=["GET", "POST"])
def legacy_login():
    """Baseline single-factor login: password only, cleartext LDAP bind, no lockout, no audit log."""
    if request.method == "GET":
        return render_template("legacy.html", result=None)
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    result = {"ok": False, "username": username}
    try:
        server = Server(LDAP_URL, use_ssl=False, connect_timeout=5)
        with Connection(server, LDAP_RO_DN, LDAP_RO_PW, auto_bind=True) as lookup:
            lookup.search(LDAP_BASE, f"(uid={escape_filter_chars(username)})", attributes=["cn", "departmentNumber"])
            if lookup.entries and password:
                entry = lookup.entries[0]
                user = Connection(server, entry.entry_dn, password)
                if user.bind():
                    result = {"ok": True, "username": username, "name": str(entry.cn),
                              "department": str(entry.departmentNumber), "dn": entry.entry_dn}
                user.unbind()
    except LDAPException as exc:
        result["error"] = type(exc).__name__
    return render_template("legacy.html", result=result), (200 if result["ok"] else 401)


@app.get("/healthz")
def healthz():
    return {"status": "UP"}
