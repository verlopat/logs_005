#!/usr/bin/env bash
# teardown.sh — cleanly stop the SecurityLog network and Gateway API

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
GATEWAY_DIR="${ROOT_DIR}/gateway"

log() { echo -e "\033[1;33m[teardown]\033[0m $*"; }

# Stop Gateway API
if [ -f "${GATEWAY_DIR}/gateway.pid" ]; then
  PID=$(cat "${GATEWAY_DIR}/gateway.pid")
  log "Stopping Gateway API (PID=${PID})..."
  kill "$PID" 2>/dev/null || true
  rm -f "${GATEWAY_DIR}/gateway.pid"
fi

log "Stopping Docker containers..."
docker-compose -f "${COMPOSE_FILE}" down --volumes --remove-orphans 2>/dev/null || true

log "Removing chaincode Docker images..."
docker images -q 'dev-peer*' 2>/dev/null | xargs -r docker rmi -f || true

log "Removing generated artifacts..."
rm -rf "${ROOT_DIR}/blockchain/network/crypto-config"
rm -rf "${ROOT_DIR}/blockchain/network/channel-artifacts"
rm -f  "${ROOT_DIR}/security_logger.tar.gz"

log "✅  Network torn down."
