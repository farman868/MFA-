#!/usr/bin/env python3
"""
verify_mfa.py - automated verification of every practical requirement in the enterprise MFA lab.
Python 3.9+, standard library only (helpers in lab_common.py). Run after scripts/setup_lab.sh.

  Directory & IdP      1 containers  2 legacy LDAP bind  3 OIDC discovery
  MFA methods          4 Email OTP   5 SMS OTP   6 App TOTP + SSO   7 SMS fallback login
                       8 Email fallback login (accessibility)   9 initial-enrolment OTP + biometric (platform WebAuthn)
                       10 hardware token (roaming FIDO2) + admin access   11 backup (recovery) codes
  Integration          6b SSO across a second application (hr-portal)   12 RADIUS   13 OpenVPN tunnel
  Monitoring           14 events logged   15 Wazuh decodes real events   16 rules fire on replay   17 live alerts

Writes docs/evidence/verify_<UTC>.json. Exit code 0 = all checks passed.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from lab_common import (BRIDGE, EVIDENCE, HR_PORTAL, KC, LAB_USER_PASSWORD, LDAP_BASE, MAILPIT, PORTAL,  # noqa: E402
                        REALM, ROOT, BridgeAdmin, Browser, KCAdmin, VirtualAuthenticator, compose, http_json,
                        load_env, logtest, mailpit_code, portal_session_fields, read_container_file, sms_code,
                        sms_snapshot, totp, utc_stamp)

EXPECTED_RULES = {"100501", "100503", "100507", "100508", "100509", "100522", "100523", "100524", "100526", "100532"}
RESULTS: list[dict] = []


def check(name: str):
    def deco(fn):
        def run(*a, **kw):
            t0 = time.time()
            try:
                detail = fn(*a, **kw) or ""
                RESULTS.append({"check": name, "status": "PASS", "detail": detail, "seconds": round(time.time() - t0, 1)})
                print(f"  \033[32mPASS\033[0m  {name}\n        {detail}")
            except Exception as exc:  # noqa: BLE001 - every failure is recorded, the run continues
                RESULTS.append({"check": name, "status": "FAIL", "detail": str(exc), "seconds": round(time.time() - t0, 1)})
                print(f"  \033[31mFAIL\033[0m  {name}\n        {exc}")
        return run
    return deco


def login(b: Browser, username: str, password: str, start: str = PORTAL) -> Browser:
    b.get(f"{start}/login")
    return b.submit(b.form("kc-form-login"), username=username, password=password)


def expect_portal(b: Browser, aal: str, method: str, base: str = PORTAL) -> dict:
    got = portal_session_fields(b.body)
    if not b.url.startswith(f"{base}/me") or got != {"aal": aal, "mfa_method": method}:
        raise RuntimeError(f"expected {aal}/{method} at {base}/me, got {got} at {b.url} ({b.message()})")
    return got


# ------------------------------------------------------------------------------------------- checks

@check("1. Containers running")
def c_containers():
    r = compose("ps", "--format", "json")
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    out = r.stdout.strip()
    rows = json.loads(out) if out.startswith("[") else [json.loads(x) for x in out.splitlines() if x.strip()]
    state = {row["Service"]: row.get("Health") or row.get("State") for row in rows}
    needed = ["openldap", "postgres", "keycloak", "mailpit", "mfa-otp-bridge", "corp-portal", "hr-portal",
              "freeradius", "openvpn", "wazuh-manager"]
    bad = {s: state.get(s, "missing") for s in needed if state.get(s) not in ("healthy", "running")}
    if bad:
        raise RuntimeError(f"not ready: {bad}")
    return f"{len(needed)} services up"


@check("2. Directory: legacy LDAP simple bind (baseline single factor)")
def c_ldap():
    dn = f"uid=j.doe,ou=GeneralStaff,{LDAP_BASE}"
    good = compose("exec", "-T", "openldap", "ldapwhoami", "-x", "-H", "ldap://localhost", "-D", dn, "-w", LAB_USER_PASSWORD)
    bad = compose("exec", "-T", "openldap", "ldapwhoami", "-x", "-H", "ldap://localhost", "-D", dn, "-w", "wrong-password")
    if good.returncode != 0 or "dn:" not in good.stdout:
        raise RuntimeError(f"valid bind failed: {good.stderr.strip()}")
    if bad.returncode == 0:
        raise RuntimeError("bind with a wrong password succeeded")
    return "password-only bind over cleartext ldap:// succeeds; wrong password rejected"


@check("3. Keycloak OIDC discovery (enterprise-realm)")
def c_discovery():
    status, doc = http_json(f"{KC}/realms/{REALM}/.well-known/openid-configuration")
    if status != 200 or doc.get("issuer") != f"{KC}/realms/{REALM}":
        raise RuntimeError(f"HTTP {status}, issuer {doc.get('issuer')}")
    return f"issuer {doc['issuer']}, PKCE S256 {'S256' in doc.get('code_challenge_methods_supported', [])}"


def _bridge_roundtrip(env, username, channel, destination, read_code) -> str:
    key = {"X-Bridge-Key": env["BRIDGE_API_KEY"]}
    since = time.time()
    s, sent = http_json(f"{BRIDGE}/otp/send", {"username": username, "channel": channel, "destination": destination,
                                               "realm": REALM, "client_id": "verify_mfa", "ip_address": "127.0.0.1"}, key)
    if s != 200:
        raise RuntimeError(f"/otp/send HTTP {s} {sent}")
    code = read_code(since)
    if not code:
        raise RuntimeError("OTP not delivered")
    cid = sent["challenge_id"]
    wrong = "000000" if code != "000000" else "111111"
    s_bad, r_bad = http_json(f"{BRIDGE}/otp/verify", {"challenge_id": cid, "code": wrong}, key)
    s_ok, _ = http_json(f"{BRIDGE}/otp/verify", {"challenge_id": cid, "code": code}, key)
    s_rep, _ = http_json(f"{BRIDGE}/otp/verify", {"challenge_id": cid, "code": code}, key)
    if (s_bad, r_bad.get("error")) != (401, "invalid_otp") or s_ok != 200 or s_rep == 200:
        raise RuntimeError(f"wrong={s_bad}/{r_bad} correct={s_ok} replay={s_rep}")
    return f"sent to {sent['masked_destination']}; wrong code rejected; correct accepted; replay rejected"


@check("4. Email OTP: mfa-otp-bridge -> Mailpit (l.fernandes)")
def c_email_otp(env):
    to = "l.fernandes@corp.enterprise.local"
    return _bridge_roundtrip(env, "l.fernandes", "email", to, lambda since: mailpit_code(to, since))


@check("5. SMS OTP: mfa-otp-bridge -> mock SMS gateway (j.doe)")
def c_sms_otp(env):
    to = "+919000000007"
    before = sms_snapshot(to)
    return _bridge_roundtrip(env, "j.doe", "sms", to, lambda since: sms_code(to, before))


@check("6. App-based TOTP + SSO: svc.mfa-probe -> corp-portal (AAL2/totp), /finance yes, /admin no")
def c_sso_totp(env, ctx):
    b = login(Browser(), "svc.mfa-probe", env["SVC_PROBE_PASSWORD"])
    b.submit(b.form("kc-otp-login-form"), otp=totp(env["SVC_PROBE_TOTP_SEED"]))
    expect_portal(b, "AAL2", "totp")
    b.get(f"{PORTAL}/finance")
    if "Access granted" not in b.body:
        raise RuntimeError("/finance denied at AAL2")
    b.get(f"{PORTAL}/admin")
    if "Higher assurance required" not in b.body:
        raise RuntimeError("AAL2 session allowed into /admin")
    ctx["probe_browser"] = b
    return "Keycloak OTP form -> portal shows AAL2/totp; /finance granted; /admin denied (needs AAL3 + it-admins)"


@check("6b. SSO across applications: same session opens hr-portal without re-authentication")
def c_sso_second_app(ctx):
    b = ctx.get("probe_browser")
    if b is None:
        raise RuntimeError("depends on check 6, which failed")
    b.get(f"{HR_PORTAL}/login")
    if b.has_form("kc-form-login"):
        raise RuntimeError("Keycloak asked for credentials again")
    expect_portal(b, "AAL2", "totp", base=HR_PORTAL)
    return "hr-portal (second OIDC client) signed in silently from the Keycloak SSO session"


@check("7. SMS OTP fallback sign-in: j.doe (no smartphone) -> AAL2/sms-otp")
def c_sso_sms_fallback():
    to = "+919000000007"
    before = sms_snapshot(to)
    b = login(Browser(), "j.doe", LAB_USER_PASSWORD)
    b.submit(b.form("kc-bridge-otp-choose"), channel="sms")
    code = sms_code(to, before)
    if not code:
        raise RuntimeError("SMS not received")
    b.submit(b.form("kc-bridge-otp-verify"), otp=code, action="verify")
    expect_portal(b, "AAL2", "sms-otp")
    return "password -> choose SMS -> code from mock handset -> portal AAL2/sms-otp"


@check("8. Email OTP fallback sign-in: l.fernandes (screen-reader user) -> AAL1/email-otp")
def c_sso_email_fallback():
    to = "l.fernandes@corp.enterprise.local"
    b = login(Browser(), "l.fernandes", LAB_USER_PASSWORD)
    since = time.time()
    b.submit(b.form("kc-bridge-otp-choose"), channel="email")
    code = mailpit_code(to, since)
    if not code:
        raise RuntimeError("email not received")
    b.submit(b.form("kc-bridge-otp-verify"), otp=code, action="verify")
    expect_portal(b, "AAL1", "email-otp")
    b.get(f"{PORTAL}/finance")
    if "Higher assurance required" not in b.body:
        raise RuntimeError("email-OTP (AAL1) session was allowed into /finance")
    return "portal AAL1/email-otp; /finance correctly requires AAL2"


def _webauthn_journey(admin: KCAdmin, username: str, kind: str) -> tuple[Browser, VirtualAuthenticator, dict]:
    user = admin.user(username)
    strong = []
    for cred in admin.credentials(user["id"]):
        if cred["type"].startswith("webauthn") and (cred.get("userLabel") or "").startswith("lab-virtual"):
            admin.call("DELETE", f"/users/{user['id']}/credentials/{cred['id']}")
        elif cred["type"] in ("otp", "webauthn", "webauthn-passwordless"):
            strong.append(cred.get("userLabel") or cred["type"])
    if strong:
        raise RuntimeError(f"{username} already has a real authenticator ({strong}); test needs an account "
                           "without one (remove it in the admin console or use scripts/teardown_lab.sh --purge)")
    va = VirtualAuthenticator(kind)
    email = user["email"]
    # First sign-in: password -> initial-enrolment Email OTP -> WebAuthn registration (required action)
    b = login(Browser(), username, LAB_USER_PASSWORD)
    choose = b.form("kc-bridge-otp-choose")
    since = time.time()
    b.submit(choose, channel="email")
    code = mailpit_code(email, since)
    if not code:
        raise RuntimeError("initial-enrolment email OTP not received")
    b.submit(b.form("kc-bridge-otp-verify"), otp=code, action="verify")
    b.submit(b.form("register"), **va.register(b.body))
    enrol = portal_session_fields(b.body)
    if enrol.get("mfa_method") != "email-otp":
        raise RuntimeError(f"enrolment session not completed: {enrol} at {b.url} ({b.message()})")
    # Second sign-in: password -> WebAuthn assertion
    b2 = login(Browser(), username, LAB_USER_PASSWORD)
    b2.submit(b2.form("webauth"), **va.assertion(b2.body))
    expect_portal(b2, "AAL3", "webauthn")
    return b2, va, enrol


@check("9. Initial-enrolment OTP + biometrics (platform WebAuthn, virtual fingerprint/face): p.nair -> AAL3")
def c_biometric(admin):
    _, va, enrol = _webauthn_journey(admin, "p.nair", "platform")
    return (f"1st sign-in: email OTP required before enrolment ({enrol['aal']}), platform authenticator registered "
            f"[{va.transport}, UV]; 2nd sign-in: WebAuthn assertion -> AAL3/webauthn")


@check("10. Hardware token (roaming FIDO2, virtual YubiKey): s.kumar -> AAL3 and /admin granted")
def c_hardware(admin):
    b, va, _ = _webauthn_journey(admin, "s.kumar", "roaming")
    b.get(f"{PORTAL}/admin")
    if "Access granted" not in b.body:
        raise RuntimeError("AAL3 it-admin was denied /admin")
    return f"security key registered [{va.transport}], assertion -> AAL3/webauthn, /admin granted (AAL3 + it-admins)"


def _select_alternative(b: Browser, keyword: str) -> None:
    tw = next((f for f in b.forms() if "tryAnotherWay" in f["fields"]), None)
    if not tw:
        raise RuntimeError("no 'Try another way' option on the OTP page")
    b.submit(tw)
    ids = re.findall(r'name="authenticationExecution"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="authenticationExecution"'
                     r"|fillAndSubmit\('([^']+)'\)", b.body)
    ids = [next(x for x in t if x) for t in ids]
    if not ids:
        raise RuntimeError("authenticator selection page not found")
    chosen = ids[-1]
    for i in ids:
        pos = b.body.find(i)
        if keyword.lower() in b.body[pos:pos + 600].lower():
            chosen = i
            break
    action = next((f["action"] for f in b.forms() if "login-actions" in f["action"]), "")
    b.post(action, {"authenticationExecution": chosen})


@check("11. Backup (recovery) codes: generate, then sign in with a backup code instead of TOTP")
def c_recovery_codes(env, admin):
    user = admin.user("svc.mfa-probe")
    rep = admin.call("GET", f"/users/{user['id']}")[1]
    rep["requiredActions"] = sorted(set(rep.get("requiredActions", [])) | {"CONFIGURE_RECOVERY_AUTHN_CODES"})
    s, res = admin.call("PUT", f"/users/{user['id']}", rep)
    if s not in (200, 204):
        raise RuntimeError(f"could not set required action: {s} {res}")
    b = login(Browser(), "svc.mfa-probe", env["SVC_PROBE_PASSWORD"])
    b.submit(b.form("kc-otp-login-form"), otp=totp(env["SVC_PROBE_TOTP_SEED"]))
    setup = next((f for f in b.forms() if any("RecoveryAuthnCodes" in k for k in f["fields"])), None)
    if not setup:
        raise RuntimeError(f"backup-code setup page not shown ({b.url}; {b.message()})")
    hidden = next(v for k, v in setup["fields"].items() if "RecoveryAuthnCodes" in k)
    codes = [c for c in re.split(r"[,\s]+", hidden) if c] or re.findall(r"\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b", b.body)
    b.submit(setup, kcRecoveryCodesConfirmationCheck="on")
    if not b.url.startswith(f"{PORTAL}/me"):
        raise RuntimeError(f"setup did not complete: {b.url} ({b.message()})")
    b2 = login(Browser(), "svc.mfa-probe", env["SVC_PROBE_PASSWORD"])
    _select_alternative(b2, "recovery")
    m = re.search(r"#\s*(\d+)", re.sub(r"<[^>]+>", " ", b2.body))
    if not m:
        raise RuntimeError(f"backup-code prompt not found ({b2.message()})")
    n = int(m.group(1))
    b2.submit(b2.form(), recoveryCodeInput=codes[n - 1])
    expect_portal(b2, "AAL2", "recovery-code")
    return f"{len(codes)} single-use backup codes issued; sign-in with code #{n} -> AAL2/recovery-code"


def _radclient(password_field: str) -> str:
    attrs = (f'User-Name = "svc.mfa-probe"\nUser-Password = "{password_field}"\n'
             'Calling-Station-Id = "198.51.100.23"\nNAS-Identifier = "verify_mfa"\n')
    r = compose("exec", "-T", "openvpn", "sh", "-c", 'radclient -t 12 -r 1 freeradius:1812 auth "$RADIUS_SHARED_SECRET"',
                input_text=attrs)
    return r.stdout + r.stderr


def _scrv1(password: str, otp: str) -> str:
    return "SCRV1:" + base64.b64encode(password.encode()).decode() + ":" + base64.b64encode(otp.encode()).decode()


@check("12. RADIUS: password+TOTP accepted; wrong OTP and password-only rejected")
def c_radius(env):
    good = _radclient(_scrv1(env["SVC_PROBE_PASSWORD"], totp(env["SVC_PROBE_TOTP_SEED"])))
    bad = _radclient(_scrv1(env["SVC_PROBE_PASSWORD"], "000000"))
    nootp = _radclient(env["SVC_PROBE_PASSWORD"])
    if "Access-Accept" not in good:
        raise RuntimeError(f"valid password+TOTP not accepted: {good.strip()[-300:]}")
    if "Access-Reject" not in bad or "Access-Reject" not in nootp:
        raise RuntimeError("wrong OTP or password-only was not rejected")
    return "Access-Accept (password+TOTP); Access-Reject (wrong OTP); Access-Reject (password only)"


@check("13. OpenVPN remote access: tunnel with password+TOTP, refused with a wrong OTP")
def c_vpn_tunnel(env):
    totp(env["SVC_PROBE_TOTP_SEED"])  # the client derives its own code; move to an unused window first
    good = compose("--profile", "vpn-test", "run", "--rm", "--build", "vpn-client", timeout=600)
    bad = compose("--profile", "vpn-test", "run", "--rm", "-e", "MODE=bad-otp", "vpn-client", timeout=300)
    out_g, out_b = good.stdout + good.stderr, bad.stdout + bad.stderr
    if "VPN_TEST_RESULT=PASS" not in out_g:
        raise RuntimeError("good: " + out_g.strip()[-400:])
    if "VPN_TEST_RESULT=PASS" not in out_b:
        raise RuntimeError("bad-otp: " + out_b.strip()[-400:])
    return "tunnel up + gateway ping with password+TOTP; AUTH_FAILED with wrong OTP"


@check("14. Monitoring: MFA usage events logged (logins, OTP sends, fallback, VPN)")
def c_logs():
    kc = read_container_file("/var/log/keycloak/keycloak.log")
    br = read_container_file("/var/log/mfa/bridge-events.log", 1000)
    need = {
        "LOGIN totp": r'\[org\.keycloak\.events\].*type="?LOGIN"?,.*mfa_method="?totp',
        "LOGIN webauthn": r'\[org\.keycloak\.events\].*type="?LOGIN"?,.*mfa_method="?webauthn',
        "LOGIN fallback": r'\[org\.keycloak\.events\].*type="?LOGIN"?,.*mfa_method="?(sms|email)-otp',
        "LOGIN_ERROR": r'\[org\.keycloak\.events\].*type="?LOGIN_ERROR',
    }
    missing = [k for k, p in need.items() if not re.search(p, kc)]
    missing += [t for t in ("SEND_OTP", "OTP_VERIFY_ERROR", "RADIUS_AUTH", "RADIUS_AUTH_ERROR") if f'type="{t}"' not in br]
    if missing:
        raise RuntimeError(f"missing: {missing}")
    return "Keycloak LOGIN (totp/webauthn/fallback), LOGIN_ERROR; bridge SEND_OTP, OTP_VERIFY_ERROR, RADIUS_AUTH(_ERROR)"


@check("15. Monitoring: Wazuh decodes a real Keycloak LOGIN event")
def c_logtest_real():
    kc = read_container_file("/var/log/keycloak/keycloak.log")
    lines = [ln for ln in kc.splitlines() if "[org.keycloak.events]" in ln and re.search(r'type="?LOGIN"?,', ln)]
    if not lines:
        raise RuntimeError("no LOGIN event in keycloak.log")
    out = logtest([lines[-1]])
    if "keycloak-events" not in out or not re.search(r"id: '1005(01|26)'", out):
        raise RuntimeError(out[-600:])
    fields = re.findall(r"(keycloak\.\w+|srcip|dstuser): '([^']*)'", out)
    return "decoded " + ", ".join(f"{k}={v}" for k, v in fields[:6])


@check("16. Monitoring: detection rules fire (brute force, OTP bombing, MFA failures, fallback, containment)")
def c_logtest_rules():
    out = logtest((ROOT / "siem" / "sample_events.log").read_text().splitlines())
    fired = set(re.findall(r"id: '(1005\d\d)'", out))
    missing = EXPECTED_RULES - fired
    if missing:
        raise RuntimeError(f"not triggered: {sorted(missing)} (fired: {sorted(fired)})")
    return "fired " + ", ".join(sorted(fired))


@check("17. Monitoring: live Wazuh manager writing MFA alerts")
def c_alerts():
    for _ in range(12):
        r = compose("exec", "-T", "wazuh-manager", "sh", "-c",
                    "grep -c '\"id\":\"1005[0-4][0-9]\"' /var/ossec/logs/alerts/alerts.json || true")
        count = int((r.stdout.strip().splitlines() or ["0"])[-1] or 0)
        if count:
            return f"{count} alerts with rule IDs 1005xx in alerts.json"
        time.sleep(5)
    raise RuntimeError("no 1005xx alerts after 60 s (run scripts/wazuh_enable_ingestion.sh)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip-vpn-tunnel", action="store_true", help="skip check 13 (needs /dev/net/tun)")
    args = ap.parse_args()
    env = load_env()
    admin, bridge, ctx = KCAdmin(env), BridgeAdmin(env), {}

    print("\nEnterprise MFA lab verification\n" + "=" * 40)
    c_containers()
    for user in ("j.doe", "l.fernandes", "p.nair", "s.kumar"):  # keep reruns repeatable
        bridge.post("/admin/unlock", username=user, operator="verify_mfa", reason="pre-test reset")
    c_ldap()
    c_discovery()
    c_email_otp(env)
    c_sms_otp(env)
    c_sso_totp(env, ctx)
    c_sso_second_app(ctx)
    c_sso_sms_fallback()
    c_sso_email_fallback()
    c_biometric(admin)
    c_hardware(admin)
    c_recovery_codes(env, admin)
    c_radius(env)
    if not args.skip_vpn_tunnel:
        c_vpn_tunnel(env)
    c_logs()
    c_logtest_real()
    c_logtest_rules()
    c_alerts()

    passed = sum(r["status"] == "PASS" for r in RESULTS)
    print("=" * 40 + f"\n{passed}/{len(RESULTS)} checks passed\n")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    stamp = utc_stamp()
    report = EVIDENCE / f"verify_{stamp}.json"
    report.write_text(json.dumps({"generated_utc": stamp, "realm": REALM, "mailpit": MAILPIT,
                                  "results": RESULTS}, indent=2))
    (EVIDENCE / "verify_latest.json").write_text(report.read_text())
    print(f"evidence: {report.relative_to(ROOT)}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
