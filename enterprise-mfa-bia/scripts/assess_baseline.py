#!/usr/bin/env python3
"""
assess_baseline.py - evidence for the current-state (pre-MFA) assessment of the sample enterprise.

Probes the legacy single-factor baseline that still exists in the lab (OpenLDAP + the /legacy intranet
login of corp-portal) and records each authentication gap as PASS (control present) or GAP (missing):

  B1 single-factor sign-in            password alone opens the legacy intranet
  B2 no account lockout               20 wrong passwords, then the right one still works
  B3 cleartext directory binds        simple bind on ldap://389 succeeds without TLS
  B4 anonymous directory read         directory entries readable without credentials
  B5 password hashes exposed          can the read-only service account read userPassword?
  B6 no directory password policy     ppolicy overlay (complexity, expiry, lockout) not loaded
  B7 no security monitoring           legacy sign-ins produce no events in the monitored logs
  B8 MFA-protected path for contrast  same user via Keycloak SSO is challenged for a second factor

Writes docs/evidence/baseline_assessment_<UTC>.json and baseline_latest.json (used by
docs/01_Assessment_Report.md). Python 3.9+, standard library only.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lab_common import (EVIDENCE, LAB_USER_PASSWORD, LDAP_BASE, PORTAL, ROOT, Browser, compose,  # noqa: E402
                        read_container_file, utc_stamp)

FINDINGS: list[dict] = []


def record(fid: str, title: str, gap: bool, evidence: str, severity: str) -> None:
    FINDINGS.append({"id": fid, "title": title, "status": "GAP" if gap else "CONTROL PRESENT",
                     "severity": severity if gap else "-", "evidence": evidence})
    colour = "\033[33mGAP \033[0m" if gap else "\033[32mOK  \033[0m"
    print(f"  {colour} {fid} {title}\n        {evidence}")


def legacy_login(username: str, password: str) -> bool:
    b = Browser().get(f"{PORTAL}/legacy")
    b.post(f"{PORTAL}/legacy", {"username": username, "password": password})
    return "with a password only" in b.body


def main() -> int:
    print("\nBaseline (pre-MFA) authentication assessment\n" + "=" * 46)
    user = "m.rao"

    ok = legacy_login(user, LAB_USER_PASSWORD)
    record("B1", "Single-factor sign-in to the legacy intranet", ok,
           f"POST /legacy as {user} with password only -> {'signed in' if ok else 'refused'}", "High")

    for _ in range(20):
        legacy_login(user, "Wrong-Guess-123")
    still = legacy_login(user, LAB_USER_PASSWORD)
    record("B2", "No account lockout on the legacy path", still,
           f"20 consecutive wrong passwords, then the correct one -> {'still signed in' if still else 'locked'}", "High")

    dn = f"uid={user},ou=GeneralStaff,{LDAP_BASE}"
    r = compose("exec", "-T", "openldap", "ldapwhoami", "-x", "-H", "ldap://localhost", "-D", dn, "-w", LAB_USER_PASSWORD)
    record("B3", "Directory accepts cleartext simple binds (no TLS required)", r.returncode == 0,
           f"ldapwhoami -x -H ldap://:389 (no StartTLS) -> {r.stdout.strip() or r.stderr.strip()}", "High")

    r = compose("exec", "-T", "openldap", "ldapsearch", "-x", "-LLL", "-H", "ldap://localhost", "-b", LDAP_BASE,
                "(objectClass=inetOrgPerson)", "uid", "mail", "mobile")
    n = r.stdout.count("uid: ")
    record("B4", "Anonymous read of the directory", n > 0,
           f"anonymous ldapsearch returned {n} user entries (names, email, mobile numbers)", "Medium")

    r = compose("exec", "-T", "openldap", "sh", "-c",
                'ldapsearch -x -LLL -H ldap://localhost -D "cn=readonly,dc=corp,dc=enterprise,dc=local" '
                f'-w "$LDAP_READONLY_USER_PASSWORD" -b "{LDAP_BASE}" "(uid={user})" userPassword')
    exposed = "userPassword" in r.stdout
    record("B5", "Password hashes readable by the service account", exposed,
           "read-only bind account " + ("CAN read userPassword (offline cracking risk)" if exposed
                                        else "cannot read userPassword"), "High")

    r = compose("exec", "-T", "openldap", "sh", "-c",
                "ldapsearch -Q -LLL -Y EXTERNAL -H ldapi:/// -b cn=config '(olcOverlay=*ppolicy*)' dn 2>/dev/null")
    has_pp = "ppolicy" in r.stdout
    record("B6", "No directory password policy / lockout (ppolicy overlay)", not has_pp,
           "ppolicy overlay " + ("loaded" if has_pp else "not configured: no complexity, expiry or lockout at the directory"),
           "Medium")

    marker = time.strftime("%Y-%m-%d %H:%M", time.gmtime())
    kc = read_container_file("/var/log/keycloak/keycloak.log", 3000)
    br = read_container_file("/var/log/mfa/bridge-events.log", 3000)
    seen = any(user in ln and ln.startswith(marker) for ln in (kc + br).splitlines())
    record("B7", "No security monitoring of legacy sign-ins", not seen,
           f"22 legacy sign-in attempts in the last minute -> "
           f"{'events found' if seen else 'no event in the Keycloak or MFA logs watched by Wazuh'}", "High")

    b = Browser().get(f"{PORTAL}/login")
    b.submit(b.form("kc-form-login"), username=user, password=LAB_USER_PASSWORD)
    challenged = b.has_form("kc-otp-login-form") or b.has_form("kc-bridge-otp-choose") or "totp" in b.body.lower()
    record("B8", "Contrast: same user through Keycloak SSO is challenged for MFA", not challenged,
           "Keycloak " + ("asked for a second factor after the password" if challenged else "did NOT ask for a second factor"),
           "High")

    gaps = [f for f in FINDINGS if f["status"] == "GAP"]
    print("=" * 46 + f"\n{len(gaps)} gaps found in {len(FINDINGS)} probes\n")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    stamp = utc_stamp()
    data = json.dumps({"generated_utc": stamp, "findings": FINDINGS}, indent=2)
    (EVIDENCE / f"baseline_assessment_{stamp}.json").write_text(data)
    (EVIDENCE / "baseline_latest.json").write_text(data)
    print(f"evidence: {(EVIDENCE / f'baseline_assessment_{stamp}.json').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
