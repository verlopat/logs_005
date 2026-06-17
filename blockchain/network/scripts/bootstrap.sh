#!/usr/bin/env bash
# bootstrap.sh — Bring up the SecurityLog Fabric network end-to-end
# Usage: bash blockchain/network/scripts/bootstrap.sh
# Requires: docker, docker-compose (or docker compose), node>=18, npm
# NOTE: cryptogen / configtxgen / peer are auto-downloaded if not in PATH.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT_DIR="$(cd "${NET_DIR}/../.." && pwd)"

CHANNEL_NAME="securitylogchannel"
CHAINCODE_NAME="security_logger"
CHAINCODE_VERSION="1.0"
CHAINCODE_SEQUENCE=1
CC_PATH="${ROOT_DIR}/blockchain/chaincode/security_logger"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
GATEWAY_DIR="${ROOT_DIR}/gateway"
FABRIC_VERSION="2.5.9"
CA_VERSION="1.5.12"
BIN_DIR="${ROOT_DIR}/.fabric-bin"

log()  { echo -e "\033[1;36m[bootstrap]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[bootstrap]\033[0m ✅  $*"; }
err()  { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }

# ── 0. Ensure Fabric binaries are available ──────────────────────────────────
log "Checking Fabric binaries..."

if ! command -v cryptogen &>/dev/null || ! command -v configtxgen &>/dev/null; then
  warn "cryptogen/configtxgen not found in PATH — downloading Fabric ${FABRIC_VERSION} binaries..."
  mkdir -p "${BIN_DIR}"
  INSTALL_SCRIPT="${BIN_DIR}/install-fabric.sh"
  curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh \
    -o "${INSTALL_SCRIPT}"
  chmod +x "${INSTALL_SCRIPT}"
  # Download only binaries (b) — no docker images (d) or samples (s)
  cd "${BIN_DIR}" && bash "${INSTALL_SCRIPT}" --fabric-version "${FABRIC_VERSION}" \
    --ca-version "${CA_VERSION}" b 2>&1 | tail -20
  cd "${ROOT_DIR}"
  # The script places binaries in ./bin relative to where it was run
  export PATH="${BIN_DIR}/bin:${PATH}"
  ok "Fabric binaries installed at ${BIN_DIR}/bin"
else
  ok "Fabric binaries found in PATH"
fi

# Re-export PATH so all subsequent steps see the binaries
export PATH="${BIN_DIR}/bin:${PATH}"

# Sanity check
cryptogen  version || err "cryptogen still not available after download"
configtxgen --version || err "configtxgen still not available after download"

# ── 1. Crypto material ───────────────────────────────────────────────────────
log "Generating crypto material..."
cd "${NET_DIR}"
export FABRIC_CFG_PATH="${NET_DIR}"
cryptogen generate --config=crypto-config.yaml --output=crypto-config \
  || err "cryptogen failed"
ok "Crypto material generated."

# ── 2. Genesis block + channel TX ───────────────────────────────────────────
log "Generating genesis block..."
mkdir -p channel-artifacts

configtxgen -profile SecurityLogGenesis -channelID system-channel \
  -outputBlock channel-artifacts/genesis.block \
  || err "configtxgen genesis failed"

log "Generating channel TX..."
configtxgen -profile SecurityLogChannel \
  -outputCreateChannelTx channel-artifacts/${CHANNEL_NAME}.tx \
  -channelID ${CHANNEL_NAME} \
  || err "configtxgen channel TX failed"

configtxgen -profile SecurityLogChannel \
  -outputAnchorPeersUpdate channel-artifacts/CloudSecOrgMSPanchors.tx \
  -channelID ${CHANNEL_NAME} -asOrg CloudSecOrg \
  || err "configtxgen anchor TX failed"
ok "Channel artifacts generated."

# ── 3. Docker Compose ────────────────────────────────────────────────────────
log "Starting Docker containers..."
cd "${ROOT_DIR}"

# Support both 'docker-compose' (v1) and 'docker compose' (v2)
if command -v docker-compose &>/dev/null; then
  DC="docker-compose"
else
  DC="docker compose"
fi

${DC} -f "${COMPOSE_FILE}" up -d || err "Docker Compose up failed"

log "Waiting for orderer TLS to be ready..."
ORDERER_TLS_CERT="${NET_DIR}/crypto-config/ordererOrganizations/securitylog.com/orderers/orderer.securitylog.com/msp/tlscacerts/tlsca.securitylog.com-cert.pem"
for i in $(seq 1 30); do
  if [ -f "${ORDERER_TLS_CERT}" ]; then
    ok "Orderer TLS cert found (${i}s)"
    break
  fi
  sleep 1
done
[ -f "${ORDERER_TLS_CERT}" ] || err "Orderer TLS cert never appeared after 30s"

log "Waiting 10s more for peers to initialise..."
sleep 10

# ── 4. Channel create + join ─────────────────────────────────────────────────
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="CloudSecOrgMSP"
export CORE_PEER_TLS_ROOTCERT_FILE="${NET_DIR}/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer0.cloudsec.securitylog.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="${NET_DIR}/crypto-config/peerOrganizations/cloudsec.securitylog.com/users/Admin@cloudsec.securitylog.com/msp"
export CORE_PEER_ADDRESS="localhost:7051"
export ORDERER_CA="${ORDERER_TLS_CERT}"

log "Creating channel ${CHANNEL_NAME}..."
peer channel create \
  -o localhost:7050 -c ${CHANNEL_NAME} \
  -f ${NET_DIR}/channel-artifacts/${CHANNEL_NAME}.tx \
  --outputBlock ${NET_DIR}/channel-artifacts/${CHANNEL_NAME}.block \
  --tls --cafile "${ORDERER_CA}" \
  || err "peer channel create failed"

log "Joining peer0 (localhost:7051)..."
export CORE_PEER_ADDRESS="localhost:7051"
peer channel join -b ${NET_DIR}/channel-artifacts/${CHANNEL_NAME}.block \
  || err "peer0 join failed"

log "Joining peer1 (localhost:8051)..."
export CORE_PEER_ADDRESS="localhost:8051"
peer channel join -b ${NET_DIR}/channel-artifacts/${CHANNEL_NAME}.block \
  || err "peer1 join failed"

export CORE_PEER_ADDRESS="localhost:7051"

log "Updating anchor peer..."
peer channel update \
  -o localhost:7050 -c ${CHANNEL_NAME} \
  -f ${NET_DIR}/channel-artifacts/CloudSecOrgMSPanchors.tx \
  --tls --cafile "${ORDERER_CA}" \
  || err "anchor peer update failed"
ok "Channel created and peers joined."

# ── 5. Chaincode lifecycle ────────────────────────────────────────────────────
log "Building chaincode (go mod tidy)..."
cd "${CC_PATH}" && go mod tidy && cd "${ROOT_DIR}"

log "Packaging chaincode..."
peer lifecycle chaincode package \
  ${CHAINCODE_NAME}.tar.gz \
  --path ${CC_PATH} --lang golang \
  --label ${CHAINCODE_NAME}_${CHAINCODE_VERSION} \
  || err "chaincode package failed"

export CORE_PEER_ADDRESS="localhost:7051"
log "Installing on peer0..."
peer lifecycle chaincode install ${CHAINCODE_NAME}.tar.gz \
  || err "chaincode install peer0 failed"

export CORE_PEER_ADDRESS="localhost:8051"
log "Installing on peer1..."
peer lifecycle chaincode install ${CHAINCODE_NAME}.tar.gz \
  || err "chaincode install peer1 failed"
export CORE_PEER_ADDRESS="localhost:7051"

# Extract package ID — handle both space-separated and colon-delimited output formats
PACKAGE_ID=$(peer lifecycle chaincode queryinstalled 2>/dev/null \
  | grep -m1 "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" \
  | grep -oP 'Package ID: \K[^,]+' \
  || peer lifecycle chaincode queryinstalled 2>/dev/null \
  | grep -m1 "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" \
  | awk -F'[, ]+' '{print $3}')

[ -n "${PACKAGE_ID}" ] || err "Could not extract package ID from queryinstalled output"
log "Package ID: ${PACKAGE_ID}"

log "Approving chaincode for org..."
peer lifecycle chaincode approveformyorg \
  -o localhost:7050 --channelID ${CHANNEL_NAME} \
  --name ${CHAINCODE_NAME} --version ${CHAINCODE_VERSION} \
  --package-id ${PACKAGE_ID} --sequence ${CHAINCODE_SEQUENCE} \
  --tls --cafile "${ORDERER_CA}" \
  || err "chaincode approveformyorg failed"

log "Committing chaincode..."
PEER0_TLS="${NET_DIR}/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer0.cloudsec.securitylog.com/tls/ca.crt"
peer lifecycle chaincode commit \
  -o localhost:7050 --channelID ${CHANNEL_NAME} \
  --name ${CHAINCODE_NAME} --version ${CHAINCODE_VERSION} \
  --sequence ${CHAINCODE_SEQUENCE} \
  --tls --cafile "${ORDERER_CA}" \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "${PEER0_TLS}" \
  || err "chaincode commit failed"

peer lifecycle chaincode querycommitted \
  --channelID ${CHANNEL_NAME} --name ${CHAINCODE_NAME}
ok "Chaincode deployed."

# ── 6. Start Node.js Gateway API ──────────────────────────────────────────────
log "Installing Gateway API dependencies..."
cd "${GATEWAY_DIR}" && npm install

# Kill any stale gateway process from a previous run
if [ -f "${GATEWAY_DIR}/gateway.pid" ]; then
  OLD_PID=$(cat "${GATEWAY_DIR}/gateway.pid")
  if kill -0 "${OLD_PID}" 2>/dev/null; then
    warn "Killing stale gateway process PID=${OLD_PID}"
    kill "${OLD_PID}" && sleep 1
  fi
  rm -f "${GATEWAY_DIR}/gateway.pid"
fi

log "Starting Gateway API in background (logs: gateway/gateway.log)..."
nohup node "${GATEWAY_DIR}/server.js" \
  > "${GATEWAY_DIR}/gateway.log" 2>&1 &
GATEWAY_PID=$!
echo $GATEWAY_PID > "${GATEWAY_DIR}/gateway.pid"

# Wait up to 15s for port 3000 to open
log "Waiting for Gateway API to start on port 3000 (up to 15s)..."
for i in $(seq 1 15); do
  if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
    ok "Gateway API running (PID=${GATEWAY_PID}) on http://localhost:3000"
    break
  fi
  sleep 1
done

# Final check
if ! curl -sf http://localhost:3000/health > /dev/null 2>&1; then
  err "Gateway API failed to start after 15s. Check gateway/gateway.log"
fi

ok "\nSecurityLog network is fully up. Run:\n\n  source .venv/bin/activate && python3 Main.py\n"
