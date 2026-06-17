#!/usr/bin/env bash
# teardown.sh — Cleanly stop the SecurityLog Fabric network
# Usage: bash blockchain/network/scripts/teardown.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
GATEWAY_DIR="${ROOT_DIR}/gateway"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

log() { echo -e "\033[1;36m[teardown]\033[0m $*"; }
ok()  { echo -e "\033[1;32m[teardown]\033[0m ✅  $*"; }

# Kill gateway process
if [ -f "${GATEWAY_DIR}/gateway.pid" ]; then
  PID=$(cat "${GATEWAY_DIR}/gateway.pid")
  if kill -0 "${PID}" 2>/dev/null; then
    log "Stopping Gateway API (PID=${PID})..."
    kill "${PID}" && sleep 1
    ok "Gateway stopped."
  fi
  rm -f "${GATEWAY_DIR}/gateway.pid"
fi

# Detect docker-compose v1 vs v2
if command -v docker-compose &>/dev/null; then
  DC="docker-compose"
else
  DC="docker compose"
fi

log "Stopping Docker containers..."
${DC} -f "${COMPOSE_FILE}" down --volumes --remove-orphans 2>/dev/null || true
ok "Containers stopped and volumes removed."

log "Cleaning up generated artifacts..."
NET_DIR="${ROOT_DIR}/blockchain/network"
rm -rf "${NET_DIR}/crypto-config" \
       "${NET_DIR}/channel-artifacts" \
       "${ROOT_DIR}/security_logger.tar.gz"
ok "Artifacts cleaned."

ok "Teardown complete."
