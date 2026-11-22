#!/usr/bin/env python3
"""
simulate_ir_drill.py - simulated MFA security incident, detection and containment against the live lab.

Scenario "OTP bombing after credential stuffing" against j.doe (SMS/Email OTP fallback tier):
  0. Baseline   - the real j.doe signs in normally with SMS OTP (creates an active SSO session).
  1. Attack     - attacker tries leaked passwords, then the correct one (credential stuffing).
  2. Attack     - attacker floods j.doe's phone with OTP requests (MFA fatigue / OTP bombing).
  3. Attack     - attacker guesses OTP codes (repeated failed MFA attempts).
  4. Detect     - wait for the Wazuh alerts (rules 100522 OTP bombing, 100523 repeated MFA failures).
  5. Contain    - revoke all of j.doe's sessions, disable (lock) the account, lock the OTP channel,
                  then prove the containment (no sessions, SSO cookie dead, correct password refused).
  6. Evidence   - Keycloak + bridge event logs, Wazuh alerts, timeline and an after-action report in
                  docs/evidence/ir_drill_<UTC>/, and the report is inserted into
                  docs/06_Monitoring_and_Incident_Response_Plan.md.
  7. Recover    - re-enable the account and OTP channel, clear lockout (skip with --no-recover).

Every number in the report comes from what this run observed. Python 3.9+, standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lab_common import (EVIDENCE, KC, LAB_USER_PASSWORD, LDAP_BASE, PORTAL, REALM, ROOT, BridgeAdmin,  # noqa: E402
                        Browser, KCAdmin, alert_user, alerts_since, compose, lines_since, load_env, logtest,
                        read_container_file, sms_code, sms_snapshot)

TARGET = "j.doe"
TARGET_DN = f"uid=j.doe,ou=GeneralStaff,{LDAP_BASE}"
TARGET_PHONE = "+919000000007"
LEAKED_PASSWORDS = ["Summer2025!", "Welcome@123", "Corp@2025", "Password1!"]
DETECTION_RULES = {"100522": "OTP bombing / MFA fatigue", "100523": "Repeated MFA failures"}
DOC = ROOT / "docs" / "06_Monitoring_and_Incident_Response_Plan.md"
BEGIN, END = "<!-- DRILL-RESULTS:BEGIN -->", "<!-- DRILL-RESULTS:END -->"

TIMELINE: list[dict] = []
CONSOLE: list[str] = []


def now() -> datetime:
    return datetime.now(timezone.utc)


def event(phase: str, actor: str, action: str, result: str) -> None:
    t = now()
    TIMELINE.append({"utc": t.strftime("%Y-%m-%dT%H:%M:%S"), "phase": phase, "actor": actor,
                     "action": action, "result": result})
    line = f"[{t.strftime('%H:%M:%S')}Z] {phase:<9} {actor:<9} {action} -> {result}"
    CONSOLE.append(line)
    print(line)


def keycloak_login_page(b: Browser) -> Browser:
    return b.get(f"{PORTAL}/login")


# ----------------------------------------------------------------------------------------- phases

def phase0_baseline() -> Browser:
    before = sms_snapshot(TARGET_PHONE)
    b = keycloak_login_page(Browser())
    b.submit(b.form("kc-form-login"), username=TARGET, password=LAB_USER_PASSWORD)
    b.submit(b.form("kc-bridge-otp-choose"), channel="sms")
    code = sms_code(TARGET_PHONE, before)
    if not code:
        raise SystemExit("baseline: SMS OTP not delivered - is the lab healthy? (run verify_mfa.py)")
    b.submit(b.form("kc-bridge-otp-verify"), otp=code, action="verify")
    ok = b.url.startswith(f"{PORTAL}/me")
    event("baseline", "user", "j.doe signs in normally with SMS OTP", "active SSO session" if ok else f"failed ({b.message()})")
    return b


def phase1_credential_stuffing() -> Browser:
    a = Browser()
    for pw in LEAKED_PASSWORDS:
        keycloak_login_page(a)
        a.submit(a.form("kc-form-login"), username=TARGET, password=pw)
        event("attack", "attacker", "credential stuffing: leaked password", a.message() or "rejected")
        time.sleep(1.6)  # slower than Keycloak's quick-login check, like a careful attacker
    keycloak_login_page(a)
    a.submit(a.form("kc-form-login"), username=TARGET, password=LAB_USER_PASSWORD)
    reached = a.has_form("kc-bridge-otp-choose")
    event("attack", "attacker", "credential stuffing: correct password from breach corpus",
          "password accepted - MFA challenge reached" if reached else f"blocked ({a.message()})")
    return a


def phase2_otp_bombing(a: Browser) -> dict:
    stats = {"sent": 0, "throttled": 0}
    if not a.has_form("kc-bridge-otp-choose"):
        event("attack", "attacker", "OTP bombing", "skipped - MFA page not reached")
        return stats
    a.submit(a.form("kc-bridge-otp-choose"), channel="sms")
    for i in range(6):
        if i:
            resend = next((f for f in a.forms() if f["id"] == "kc-bridge-otp-resend"), None)
            if not resend:
                break
            a.submit(resend, action="resend")
        throttled = "Too many codes" in a.body
        stats["throttled" if throttled else "sent"] += 1
        event("attack", "attacker", f"OTP bombing: SMS request #{i + 1}",
              "refused by rate limit" if throttled else "SMS sent to victim's phone")
        time.sleep(1.0)
    return stats


def phase3_otp_guessing(a: Browser) -> int:
    attempts = 0
    for _ in range(6):
        if not a.has_form("kc-bridge-otp-verify"):
            break
        guess = f"{secrets.randbelow(1_000_000):06d}"
        a.submit(a.form("kc-bridge-otp-verify"), otp=guess, action="verify")
        attempts += 1
        event("attack", "attacker", f"OTP guess {guess}", a.message() or "rejected")
        if a.url.startswith(PORTAL):
            event("attack", "attacker", "OTP guess", "!!! guessed correctly - account compromised")
            break
        time.sleep(1.6)
    return attempts


def phase4_detect(since_iso: str, timeout: int) -> tuple[list[dict], str]:
    deadline = time.time() + timeout
    seen: list[dict] = []
    while time.time() < deadline:
        seen = [a for a in alerts_since(since_iso) if alert_user(a) == TARGET]
        if set(DETECTION_RULES) <= {str(a["rule"]["id"]) for a in seen}:
            break
        time.sleep(5)
    fired = {str(a["rule"]["id"]) for a in seen}
    for rid, name in DETECTION_RULES.items():
        first = next((a for a in seen if str(a["rule"]["id"]) == rid), None)
        event("detect", "wazuh", f"rule {rid} ({name})",
              f"ALERT level {first['rule']['level']} at {first['timestamp'][:19]}" if first else "not observed")
    return seen, "live" if set(DETECTION_RULES) & fired else "none"


def phase5_contain(admin: KCAdmin, bridge: BridgeAdmin, victim: Browser) -> dict:
    out: dict = {"ldap_password_scrambled": False}
    user = admin.user(TARGET)
    uid = user["id"]
    before = admin.sessions(uid)
    out["sessions_before"] = len(before)
    event("contain", "soc", "list active Keycloak sessions", f"{len(before)} active")

    s, _ = admin.call("POST", f"/users/{uid}/logout")
    after = admin.sessions(uid)
    out["sessions_after"] = len(after)
    event("contain", "soc", "revoke all sessions (Admin API users/{id}/logout)", f"HTTP {s}; {len(after)} sessions remain")

    rep = admin.call("GET", f"/users/{uid}")[1]
    rep["enabled"] = False
    s, body = admin.call("PUT", f"/users/{uid}", rep)
    enabled_now = admin.call("GET", f"/users/{uid}")[1].get("enabled")
    out["keycloak_disabled"] = enabled_now is False
    event("contain", "soc", "lock account: set enabled=false in Keycloak",
          f"HTTP {s}; enabled={enabled_now}" + (f"; {body.get('errorMessage', '')}" if s >= 300 else ""))
    if enabled_now is not False:
        # Read-only LDAP federation can refuse the change: lock at the source directory instead.
        pw = "LOCKED-" + secrets.token_urlsafe(24)
        r = compose("exec", "-T", "-e", f"NEWPW={pw}", "openldap", "sh", "-c",
                    'ldappasswd -x -H ldap://localhost -D "cn=admin,dc=corp,dc=enterprise,dc=local" '
                    f'-w "$LDAP_ADMIN_PASSWORD" -s "$NEWPW" "{TARGET_DN}"')
        out["ldap_password_scrambled"] = r.returncode == 0
        event("contain", "soc", "fallback lock: scramble password in the directory (ldappasswd)",
              "done" if r.returncode == 0 else f"failed: {r.stderr.strip()[:120]}")

    s, res = bridge.post("/admin/lock", username=TARGET, operator="ir-drill", reason="OTP bombing incident")
    out["otp_channel_locked"] = s == 200
    event("contain", "soc", "lock OTP channel at mfa-otp-bridge",
          f"HTTP {s}; revoked {res.get('revoked_challenges')} pending codes")

    # ---- prove containment
    victim.get(f"{PORTAL}/login")
    sso_dead = victim.has_form("kc-form-login")
    out["sso_cookie_revoked"] = sso_dead
    event("verify", "soc", "reuse victim's SSO cookie for a new sign-in",
          "Keycloak demands credentials again (session revoked)" if sso_dead else "still signed in!")

    probe = keycloak_login_page(Browser())
    probe.submit(probe.form("kc-form-login"), username=TARGET, password=LAB_USER_PASSWORD)
    blocked = not probe.has_form("kc-bridge-otp-choose") and not probe.url.startswith(PORTAL)
    out["login_blocked"] = blocked
    event("verify", "soc", "sign-in with the stolen (correct) password",
          f"refused: {probe.message() or 'login blocked'}" if blocked else "STILL POSSIBLE")

    bf = admin.call("GET", f"/attack-detection/brute-force/users/{uid}")[1]
    out["brute_force_state"] = bf
    event("verify", "soc", "Keycloak brute-force detector state",
          f"numFailures={bf.get('numFailures')}, temporarilyDisabled={bf.get('disabled')}")
    return out


def phase7_recover(admin: KCAdmin, bridge: BridgeAdmin, contained: dict) -> None:
    uid = admin.user(TARGET)["id"]
    rep = admin.call("GET", f"/users/{uid}")[1]
    rep["enabled"] = True
    s, _ = admin.call("PUT", f"/users/{uid}", rep)
    event("recover", "it", "re-enable account (after password reset & user verification in a real case)", f"HTTP {s}")
    s, _ = admin.call("DELETE", f"/attack-detection/brute-force/users/{uid}")
    event("recover", "it", "clear brute-force lockout", f"HTTP {s}")
    if contained.get("ldap_password_scrambled"):
        r = compose("exec", "-T", "-e", f"NEWPW={LAB_USER_PASSWORD}", "openldap", "sh", "-c",
                    'ldappasswd -x -H ldap://localhost -D "cn=admin,dc=corp,dc=enterprise,dc=local" '
                    f'-w "$LDAP_ADMIN_PASSWORD" -s "$NEWPW" "{TARGET_DN}"')
        event("recover", "it", "reset directory password (lab default restored)", "done" if r.returncode == 0 else "failed")
    s, _ = bridge.post("/admin/unlock", username=TARGET, operator="ir-drill", reason="post-incident recovery")
    event("recover", "it", "unlock OTP channel and reset rate limits", f"HTTP {s}")


# --------------------------------------------------------------------------------------- reporting

def _ts(s: str) -> datetime:
    return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def build_report(stamp: str, stats: dict, guesses: int, alerts: list[dict], mode: str, contained: dict,
                 replay_rules: set[str], recovered: bool, evidence_dir: Path) -> str:
    attack_start = next(e["utc"] for e in TIMELINE if e["phase"] == "attack")
    detect = sorted((a for a in alerts if str(a["rule"]["id"]) in DETECTION_RULES), key=lambda a: a["timestamp"])
    contain_done = [e["utc"] for e in TIMELINE if e["phase"] == "contain"][-1]
    mttd = (_ts(detect[0]["timestamp"].replace(" ", "T")) - _ts(attack_start)).total_seconds() if detect else None
    mttc = (_ts(contain_done) - _ts(detect[0]["timestamp"].replace(" ", "T"))).total_seconds() if detect else None
    by_rule: dict[str, dict] = {}
    for a in alerts:
        r = by_rule.setdefault(str(a["rule"]["id"]), {"level": a["rule"]["level"], "desc": a["rule"]["description"],
                                                      "count": 0, "first": a["timestamp"][:19]})
        r["count"] += 1
    ok = lambda b: "PASS" if b else "FAIL"  # noqa: E731
    checks = [
        ("Monitoring raised an OTP-bombing alert (100522)", "100522" in by_rule),
        ("Monitoring raised a repeated-MFA-failure alert (100523)", "100523" in by_rule),
        ("All active sessions revoked", contained.get("sessions_after") == 0),
        ("Victim's SSO cookie no longer valid", contained.get("sso_cookie_revoked")),
        ("Account locked (stolen password refused)", contained.get("login_blocked")),
        ("OTP channel locked at the bridge", contained.get("otp_channel_locked")),
        ("Attacker never obtained a session", not any("compromised" in e["result"] for e in TIMELINE)),
    ]
    lines = [
        f"### Drill execution after-action report — {stamp}",
        "",
        f"*Generated automatically by `scripts/simulate_ir_drill.py`; evidence in `{evidence_dir.relative_to(ROOT)}/`.*",
        "",
        "**Scenario:** credential stuffing followed by OTP bombing and OTP guessing against `j.doe` "
        "(SMS/Email OTP fallback tier), detected by Wazuh and contained through the Keycloak Admin API and the "
        "mfa-otp-bridge admin API.",
        "",
        "| Outcome check | Result |", "|---|---|",
        *[f"| {name} | {ok(v)} |" for name, v in checks],
        "",
        "| Metric | Value |", "|---|---|",
        f"| Attack started (UTC) | {attack_start} |",
        f"| Leaked passwords tried / OTP SMS requested / refused by rate limit | {len(LEAKED_PASSWORDS)} / "
        f"{stats['sent'] + stats['throttled']} / {stats['throttled']} |",
        f"| OTP guesses submitted | {guesses} |",
        f"| Detection source | {'live Wazuh alerts' if mode == 'live' else 'NOT DETECTED LIVE (see replay)'} |",
        f"| Time to detect (attack start → first detection alert) | {f'{mttd:.0f} s' if mttd is not None else 'n/a'} |",
        f"| Time to contain (first alert → containment complete) | {f'{mttc:.0f} s' if mttc is not None else 'n/a'} |",
        f"| Sessions before / after revocation | {contained.get('sessions_before')} / {contained.get('sessions_after')} |",
        f"| Lock method | {'Keycloak account disabled' if contained.get('keycloak_disabled') else ''}"
        f"{' + ' if contained.get('keycloak_disabled') and contained.get('ldap_password_scrambled') else ''}"
        f"{'directory password scrambled' if contained.get('ldap_password_scrambled') else ''} |",
        f"| Recovery executed | {'yes' if recovered else 'no (--no-recover)'} |",
        "",
        "**Alerts raised for j.doe during the drill (Wazuh, live):**",
        "",
        "| Rule | Level | Count | First (UTC) | Description |", "|---|---|---|---|---|",
        *[f"| {rid} | {r['level']} | {r['count']} | {r['first']} | {r['desc']} |" for rid, r in sorted(by_rule.items())],
        *(["| — | — | 0 | — | no live alerts captured |"] if not by_rule else []),
        "",
        f"**Offline replay of the captured drill logs through `wazuh-logtest`:** rules fired "
        f"{', '.join(sorted(replay_rules)) or 'none'}.",
        "",
        "**Timeline (UTC):**", "",
        "| Time | Phase | Actor | Action | Result |", "|---|---|---|---|---|",
        *[f"| {e['utc'][11:]} | {e['phase']} | {e['actor']} | {e['action']} | {e['result'].replace('|', '/')} |"
          for e in TIMELINE],
        "",
        "**Lessons learned (review and edit after the drill):**",
        "",
        "- The per-user OTP rate limit (3 per minute, 10 per hour) capped how many SMS reached the victim; keep it and "
        "alert on it (rule 100521).",
        "- The attacker held the correct password: the directory password for fallback-tier users must be reset as "
        "part of recovery, and the user moved to an authenticator app or hardware key where possible.",
        "- Revoking Keycloak sessions ends SSO, but applications that keep their own session cookie stay signed in "
        "until that cookie expires (30 min in corp-portal): configure back-channel logout for every OIDC client.",
        "- Containment was scripted end to end; in production the same API calls should be wired to the alert as an "
        "automated response with analyst approval.",
    ]
    return "\n".join(lines) + "\n"


def update_doc(report: str) -> None:
    if not DOC.exists():
        return
    text = DOC.read_text()
    block = f"{BEGIN}\n{report}{END}"
    if BEGIN in text and END in text:
        text = text[: text.index(BEGIN)] + block + text[text.index(END) + len(END):]
    else:
        text = text.rstrip() + "\n\n" + block + "\n"
    DOC.write_text(text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-recover", action="store_true", help="leave j.doe locked after the drill")
    ap.add_argument("--detect-timeout", type=int, default=120, help="seconds to wait for Wazuh alerts")
    args = ap.parse_args()
    env = load_env()
    admin, bridge = KCAdmin(env), BridgeAdmin(env)

    # Pre-drill hygiene: start from a clean, enabled account.
    uid = admin.user(TARGET)["id"]
    admin.call("DELETE", f"/attack-detection/brute-force/users/{uid}")
    rep = admin.call("GET", f"/users/{uid}")[1]
    if not rep.get("enabled", True):
        rep["enabled"] = True
        admin.call("PUT", f"/users/{uid}", rep)
    bridge.post("/admin/unlock", username=TARGET, operator="ir-drill", reason="pre-drill reset")

    stamp = now().strftime("%Y%m%dT%H%M%SZ")
    since_log = now().strftime("%Y-%m-%d %H:%M:%S")
    since_iso = now().strftime("%Y-%m-%dT%H:%M:%S")
    print(f"\nMFA incident-response drill {stamp}  (target: {TARGET}, realm: {REALM}, IdP: {KC})\n" + "=" * 72)

    victim = phase0_baseline()
    attacker = phase1_credential_stuffing()
    stats = phase2_otp_bombing(attacker)
    guesses = phase3_otp_guessing(attacker)
    alerts, mode = phase4_detect(since_iso, args.detect_timeout)
    contained = phase5_contain(admin, bridge, victim)

    time.sleep(8)  # let the containment events reach the logs and the SIEM
    kc_lines = [ln for ln in lines_since(read_container_file("/var/log/keycloak/keycloak.log", 20000), since_log)
                if "[org.keycloak.events]" in ln]
    br_lines = lines_since(read_container_file("/var/log/mfa/bridge-events.log", 5000), since_log)
    alerts = [a for a in alerts_since(since_iso) if alert_user(a) in (TARGET, "")]
    replay = logtest(kc_lines + br_lines)
    replay_rules = set(re.findall(r"id: '(1005\d\d)'", replay))
    event("evidence", "soc", "offline replay of captured logs through wazuh-logtest", f"rules {sorted(replay_rules)}")

    recovered = False
    if not args.no_recover:
        phase7_recover(admin, bridge, contained)
        recovered = True

    out_dir = EVIDENCE / f"ir_drill_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "keycloak_events.log").write_text("\n".join(kc_lines) + "\n")
    (out_dir / "bridge_events.log").write_text("\n".join(br_lines) + "\n")
    (out_dir / "wazuh_alerts.json").write_text("\n".join(json.dumps(a) for a in alerts) + "\n")
    (out_dir / "wazuh_logtest_replay.txt").write_text(replay)
    (out_dir / "timeline.json").write_text(json.dumps({"stamp": stamp, "target": TARGET, "timeline": TIMELINE,
                                                        "containment": contained}, indent=2, default=str))
    report = build_report(stamp, stats, guesses, alerts, mode, contained, replay_rules, recovered, out_dir)
    (out_dir / "after_action_report.md").write_text(report)
    (out_dir / "drill_console.log").write_text("\n".join(CONSOLE) + "\n")
    update_doc(report)
    print("=" * 72 + f"\nevidence: {out_dir.relative_to(ROOT)}/  (report also inserted into {DOC.relative_to(ROOT)})")

    success = ("100522" in {str(a['rule']['id']) for a in alerts} or "100523" in {str(a['rule']['id']) for a in alerts}) \
        and contained.get("sessions_after") == 0 and contained.get("login_blocked")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
