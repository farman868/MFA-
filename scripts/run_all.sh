#!/usr/bin/env bash
# End-to-end run for submission evidence:
#   setup (build + provision) -> baseline assessment -> verification -> IR drill -> usage report.
# Each step writes JSON/Markdown evidence into docs/evidence/; the drill also updates docs/06.
# Lab verification pipeline
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rc=0
step() { printf '\n\033[1;35m==> %s\033[0m\n' "$*"; }
step "1/5 setup";                 ./scripts/setup_lab.sh --no-verify "$@"            || exit 1
step "2/5 baseline assessment";   python3 scripts/assess_baseline.py                  || rc=1
step "3/5 verification";          python3 scripts/verify_mfa.py ${VERIFY_ARGS:-}      || rc=1  # VERIFY_ARGS=--skip-vpn-tunnel
step "4/5 incident-response drill"; python3 scripts/simulate_ir_drill.py              || rc=1
step "5/5 MFA usage report";      python3 scripts/mfa_usage_report.py --hours 2       || rc=1
step "done (exit $rc) - evidence in docs/evidence/"
exit $rc
