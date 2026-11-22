#!/usr/bin/env python3
"""Writes the lab results to the GitHub Actions job summary ($GITHUB_STEP_SUMMARY) or stdout."""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EV = ROOT / "docs" / "evidence"


def newest(pattern: str) -> Path | None:
    files = sorted(EV.glob(pattern))
    return files[-1] if files else None


def main() -> None:
    out: list[str] = ["# Enterprise MFA lab — CI results", ""]
    ver = EV / "verify_latest.json"
    if ver.exists():
        res = json.loads(ver.read_text())["results"]
        ok = sum(r["status"] == "PASS" for r in res)
        out += [f"## Verification: {ok}/{len(res)} checks passed", "", "| Check | Result | Detail |", "|---|---|---|"]
        out += [f"| {r['check']} | {'✅' if r['status'] == 'PASS' else '❌'} | {r['detail'][:180].replace('|', '/')} |"
                for r in res]
        out.append("")
    else:
        out += ["## Verification: no results (verify_mfa.py did not run)", ""]
    base = EV / "baseline_latest.json"
    if base.exists():
        f = json.loads(base.read_text())["findings"]
        out += ["## Baseline assessment (pre-MFA)", "", "| ID | Finding | Status | Evidence |", "|---|---|---|---|"]
        out += [f"| {x['id']} | {x['title']} | {x['status']} | {x['evidence'][:150].replace('|', '/')} |" for x in f]
        out.append("")
    aar = newest("ir_drill_*/after_action_report.md")
    out += ([aar.read_text(), ""] if aar else ["## IR drill: no report (simulate_ir_drill.py did not run)", ""])
    usage = newest("mfa_usage_*.md")
    if usage:
        out += [usage.read_text(), ""]
    out.append("Download the **mfa-project-deliverables-and-evidence** artifact for the full documents and logs.")
    text = "\n".join(out)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
