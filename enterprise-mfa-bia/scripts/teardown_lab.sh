#!/usr/bin/env bash
# Stops the lab. --purge also deletes volumes (directory, Keycloak DB, logs, VPN PKI) for a clean rebuild.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/../lab" && pwd)"
if [ "${1:-}" = "--purge" ]; then
  docker compose --project-directory "$LAB" -f "$LAB/docker-compose.yml" --profile vpn-test down -v --remove-orphans
  echo "lab stopped and volumes removed (lab/.env kept)"
else
  docker compose --project-directory "$LAB" -f "$LAB/docker-compose.yml" --profile vpn-test down --remove-orphans
  echo "lab stopped (data kept; use --purge to reset)"
fi
