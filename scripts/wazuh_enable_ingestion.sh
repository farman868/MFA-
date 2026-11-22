#!/usr/bin/env bash
# Makes the Wazuh manager tail Keycloak and mfa-otp-bridge logs (shared Docker volumes) and reloads it.
# Idempotent: safe to run more than once.
set -euo pipefail
cd "$(dirname "$0")/../lab"
SVC=wazuh-manager

# Install custom decoders and rules
docker compose cp ../siem/keycloak_decoders.xml "$SVC":/var/ossec/etc/decoders/
docker compose cp ../siem/keycloak_rules.xml "$SVC":/var/ossec/etc/rules/
docker compose exec -T "$SVC" chown -R wazuh:wazuh /var/ossec/etc/decoders/ /var/ossec/etc/rules/ 2>/dev/null || true
docker compose exec -T "$SVC" chmod 660 /var/ossec/etc/decoders/keycloak_decoders.xml /var/ossec/etc/rules/keycloak_rules.xml 2>/dev/null || true

if docker compose exec -T "$SVC" grep -q "/var/log/keycloak/keycloak.log" /var/ossec/etc/ossec.conf; then
  echo "[wazuh] ingestion already configured"
else
  docker compose exec -T "$SVC" sh -c 'cat >> /var/ossec/etc/ossec.conf' < wazuh/ossec-localfiles.xml
  echo "[wazuh] localfile blocks appended"
fi
# Ensure ownership of queue sockets
docker compose exec -T "$SVC" chown -R wazuh:wazuh /var/ossec/queue/ 2>/dev/null || true
docker compose exec -T "$SVC" chmod -R 770 /var/ossec/queue/ 2>/dev/null || true

# Validate configuration + custom ruleset before restarting (wazuh-analysisd -t = test config and exit).
docker compose exec -T "$SVC" /var/ossec/bin/wazuh-analysisd -t
docker compose restart "$SVC"
for _ in $(seq 1 60); do
  if docker compose exec -T "$SVC" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; then
    echo "[wazuh] manager restarted; logtest socket ready; alerts -> /var/ossec/logs/alerts/alerts.json"
    exit 0
  fi
  sleep 2
done
echo "[wazuh] logtest socket did not come up after restart" >&2
exit 1
