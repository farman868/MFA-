#!/usr/bin/env python3
"""
mfa_usage_report.py - lightweight MFA usage report from the monitored logs (complements Wazuh alerting).

Summarises, for the last N hours of Keycloak and mfa-otp-bridge events plus Wazuh alerts:
successful sign-ins by MFA method, fallback (SMS/Email/backup code) usage, failed sign-ins and failed
OTP attempts by reason, OTP sends and rate-limit refusals, VPN authentications, per-user failure
leaders and alert counts by rule. Prints Markdown and saves docs/evidence/mfa_usage_<UTC>.md.
Usage: python3 scripts/mfa_usage_report.py [--hours 24]
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lab_common import EVIDENCE, ROOT, alerts_since, lines_since, read_container_file, utc_stamp  # noqa: E402

KV = re.compile(r'\b(\w+)="?([^",]*)"?(?:,|$)')


def parse(line: str) -> dict:
    return {k: v for k, v in KV.findall(line.split(") ", 1)[-1])}


def table(title: str, counter: Counter, head: str) -> list[str]:
    out = [f"### {title}", "", f"| {head} | Count |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in counter.most_common()] or ["| (none) | 0 |"]
    return out + [""]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    args = ap.parse_args()
    start = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    kc = [parse(ln) for ln in lines_since(read_container_file("/var/log/keycloak/keycloak.log", 50000),
                                          start.strftime("%Y-%m-%d %H:%M:%S")) if "[org.keycloak.events]" in ln]
    br = [parse(ln) for ln in lines_since(read_container_file("/var/log/mfa/bridge-events.log", 20000),
                                          start.strftime("%Y-%m-%d %H:%M:%S"))]
    logins = [e for e in kc if e.get("type") == "LOGIN"]
    by_method = Counter(e.get("mfa_method", "none (SSO cookie or no MFA step)") for e in logins)
    fallback = sum(v for k, v in by_method.items() if k in ("sms-otp", "email-otp", "recovery-code"))
    failures = [e for e in kc if e.get("type") == "LOGIN_ERROR"]
    mfa_fail = [e for e in failures if e.get("error") in ("invalid_otp", "expired_code", "too_many_attempts")
                or e.get("mfa_method")]
    sends = [e for e in br if e.get("type") == "SEND_OTP"]
    vpn = Counter(e["type"] for e in br if e.get("type", "").startswith("RADIUS_AUTH"))
    alerts = alerts_since(start.strftime("%Y-%m-%dT%H:%M:%S"))

    md = [f"## MFA usage report — last {args.hours} h (generated {utc_stamp()})", "",
          "| Indicator | Value |", "|---|---|",
          f"| Successful sign-ins | {len(logins)} |",
          f"| Fallback MFA share (SMS / Email / backup code) | {fallback} ({fallback / len(logins):.0%}) |" if logins
          else "| Fallback MFA share | 0 |",
          f"| Failed sign-ins (all reasons) | {len(failures)} |",
          f"| Failed second-factor attempts | {len(mfa_fail)} |",
          f"| OTP codes sent / refused by rate limit / refused (locked) | "
          f"{sum(1 for e in sends if not e.get('error'))} / {sum(1 for e in sends if e.get('error') == 'rate_limited')} / "
          f"{sum(1 for e in sends if e.get('error') == 'account_locked')} |",
          f"| VPN authentications OK / failed | {vpn['RADIUS_AUTH']} / {vpn['RADIUS_AUTH_ERROR']} |",
          f"| Wazuh alerts (rules 1005xx) | {len(alerts)} |", ""]
    md += table("Successful sign-ins by MFA method", by_method, "Method")
    md += table("Failed sign-ins by reason", Counter(e.get("error", "?") for e in failures), "Reason")
    md += table("Users with most failures", Counter(e.get("username", "?") for e in failures), "User")
    md += table("OTP sends by channel", Counter(e.get("channel", "?") for e in sends), "Channel")
    md += table("Alerts by rule", Counter(f"{a['rule']['id']} — {a['rule']['description'][:70]}" for a in alerts), "Rule")
    text = "\n".join(md)
    print(text)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / f"mfa_usage_{utc_stamp()}.md"
    out.write_text(text)
    print(f"\nsaved: {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
