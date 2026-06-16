#!/usr/bin/env bash
# teardown.sh — cleanly stop and remove the SecurityLog Fabric network
# Usage: bash blockchain/network/scripts/teardown.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

log() { echo -e "\033[1;33m[teardown]\033[0m $*"; }

log "Stopping containers..."
docker-compose -f "${COMPOSE_FILE}" down --volumes --remove-orphans 2>/dev/null || true

log "Removing chaincode images..."
docker images -q "dev-peer*" 2>/dev/null | xargs -r docker rmi -f || true

log "Removing generated artifacts..."
rm -rf "${ROOT_DIR}/blockchain/network/crypto-config"
rm -rf "${ROOT_DIR}/blockchain/network/channel-artifacts"
rm -f  "${ROOT_DIR}/blockchain/chaincode/security_logger/security_logger.tar.gz"
rm -f  "${ROOT_DIR}/security_logger.tar.gz"

log "✅  Network torn down and artifacts cleaned."
