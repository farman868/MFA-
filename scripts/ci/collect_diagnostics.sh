#!/usr/bin/env bash
# Collects container state and logs into diagnostics/ for the CI artifact (never copies lab/.env).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LAB="$ROOT/lab"; OUT="$ROOT/diagnostics"
mkdir -p "$OUT"
dc() { docker compose --project-directory "$LAB" -f "$LAB/docker-compose.yml" --profile vpn-test "$@"; }

dc ps -a > "$OUT/compose_ps.txt" 2>&1
for svc in $(dc config --services 2>/dev/null); do
  dc logs --no-color --timestamps "$svc" > "$OUT/container_${svc}.log" 2>&1
done
dc exec -T wazuh-manager tail -n 3000 /var/ossec/logs/alerts/alerts.log > "$OUT/wazuh_alerts.log" 2>&1
dc exec -T wazuh-manager tail -n 1000 /var/ossec/logs/ossec.log      > "$OUT/wazuh_ossec.log" 2>&1
dc exec -T wazuh-manager tail -n 3000 /var/log/keycloak/keycloak.log  > "$OUT/keycloak_file.log" 2>&1
dc exec -T wazuh-manager tail -n 3000 /var/log/mfa/bridge-events.log  > "$OUT/bridge_events.log" 2>&1
{ date -u; uname -a; docker version; docker compose version; free -m; df -h /; docker system df; } > "$OUT/runner.txt" 2>&1
echo "diagnostics written to $OUT"
