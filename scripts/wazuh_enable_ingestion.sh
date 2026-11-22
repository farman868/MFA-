#!/usr/bin/env bash
# Makes the Wazuh manager tail Keycloak and mfa-otp-bridge logs (shared Docker volumes) and reloads it.
# Idempotent: safe to run more than once.
set -euo pipefail
cd "$(dirname "$0")/../lab"
SVC=wazuh-manager
if docker compose exec -T "$SVC" grep -q "/var/log/keycloak/keycloak.log" /var/ossec/etc/ossec.conf; then
  echo "[wazuh] ingestion already configured"
else
  docker compose exec -T "$SVC" sh -c 'cat >> /var/ossec/etc/ossec.conf' < wazuh/ossec-localfiles.xml
  echo "[wazuh] localfile blocks appended"
fi
# Validate configuration + custom ruleset before restarting (wazuh-analysisd -t = test config and exit).
docker compose exec -T "$SVC" /var/ossec/bin/wazuh-analysisd -t
docker compose exec -T "$SVC" /var/ossec/bin/wazuh-control restart >/dev/null
for _ in $(seq 1 30); do
  if docker compose exec -T "$SVC" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"; then
    echo "[wazuh] manager restarted; alerts -> /var/ossec/logs/alerts/alerts.json"
    exit 0
  fi
  sleep 2
done
echo "[wazuh] analysisd did not come back after restart" >&2
exit 1
