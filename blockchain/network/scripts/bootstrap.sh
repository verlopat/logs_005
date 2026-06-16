#!/usr/bin/env bash
# bootstrap.sh — Bring up the SecurityLog Fabric network end-to-end
# Usage: bash blockchain/network/scripts/bootstrap.sh
# Requires: cryptogen, configtxgen, peer, docker, docker-compose

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

log() { echo -e "\033[1;36m[bootstrap]\033[0m $*"; }
err() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

# ── 1. Crypto material ────────────────────────────────────────────────────────
log "Generating crypto material..."
cd "${NET_DIR}"
cryptogen generate --config=crypto-config.yaml --output=crypto-config \
  || err "cryptogen failed"

# ── 2. Genesis block + channel TX ─────────────────────────────────────────────
log "Generating genesis block..."
export FABRIC_CFG_PATH="${NET_DIR}"
mkdir -p channel-artifacts
configtxgen -profile SecurityLogGenesis -channelID system-channel \
  -outputBlock channel-artifacts/genesis.block \
  || err "configtxgen genesis failed"

log "Generating channel creation TX..."
configtxgen -profile SecurityLogChannel -outputCreateChannelTx \
  channel-artifacts/${CHANNEL_NAME}.tx -channelID ${CHANNEL_NAME} \
  || err "configtxgen channel TX failed"

log "Generating anchor peer update TX..."
configtxgen -profile SecurityLogChannel -outputAnchorPeersUpdate \
  channel-artifacts/CloudSecOrgMSPanchors.tx \
  -channelID ${CHANNEL_NAME} -asOrg CloudSecOrg \
  || err "configtxgen anchor TX failed"

# ── 3. Docker Compose ─────────────────────────────────────────────────────────
log "Starting Docker containers..."
docker-compose -f "${COMPOSE_FILE}" up -d \
  || err "docker-compose up failed"

log "Waiting 10s for peers to initialise..."
sleep 10

# ── 4. Create and join channel ────────────────────────────────────────────────
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="CloudSecOrgMSP"
export CORE_PEER_TLS_ROOTCERT_FILE="${NET_DIR}/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer0.cloudsec.securitylog.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="${NET_DIR}/crypto-config/peerOrganizations/cloudsec.securitylog.com/users/Admin@cloudsec.securitylog.com/msp"
export CORE_PEER_ADDRESS="localhost:7051"
export ORDERER_CA="${NET_DIR}/crypto-config/ordererOrganizations/securitylog.com/orderers/orderer.securitylog.com/msp/tlscacerts/tlsca.securitylog.com-cert.pem"

log "Creating channel ${CHANNEL_NAME}..."
peer channel create \
  -o localhost:7050 \
  -c ${CHANNEL_NAME} \
  -f ${NET_DIR}/channel-artifacts/${CHANNEL_NAME}.tx \
  --outputBlock ${NET_DIR}/channel-artifacts/${CHANNEL_NAME}.block \
  --tls --cafile "${ORDERER_CA}" \
  || err "channel create failed"

log "Joining peer0 to channel..."
peer channel join -b ${NET_DIR}/channel-artifacts/${CHANNEL_NAME}.block \
  || err "peer0 join failed"

log "Joining peer1 to channel..."
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

# ── 5. Package and install chaincode ──────────────────────────────────────────
log "Building chaincode..."
cd "${CC_PATH}" && go mod tidy && cd "${ROOT_DIR}"

log "Packaging chaincode..."
peer lifecycle chaincode package \
  ${CHAINCODE_NAME}.tar.gz \
  --path ${CC_PATH} \
  --lang golang \
  --label ${CHAINCODE_NAME}_${CHAINCODE_VERSION} \
  || err "chaincode package failed"

log "Installing chaincode on peer0..."
peer lifecycle chaincode install ${CHAINCODE_NAME}.tar.gz \
  || err "chaincode install peer0 failed"

log "Installing chaincode on peer1..."
export CORE_PEER_ADDRESS="localhost:8051"
peer lifecycle chaincode install ${CHAINCODE_NAME}.tar.gz \
  || err "chaincode install peer1 failed"
export CORE_PEER_ADDRESS="localhost:7051"

# ── 6. Approve and commit chaincode ───────────────────────────────────────────
PACKAGE_ID=$(peer lifecycle chaincode queryinstalled \
  | grep ${CHAINCODE_NAME}_${CHAINCODE_VERSION} \
  | awk '{print $3}' | tr -d ',')

log "Package ID: ${PACKAGE_ID}"

log "Approving chaincode for CloudSecOrg..."
peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --channelID ${CHANNEL_NAME} \
  --name ${CHAINCODE_NAME} \
  --version ${CHAINCODE_VERSION} \
  --package-id ${PACKAGE_ID} \
  --sequence ${CHAINCODE_SEQUENCE} \
  --tls --cafile "${ORDERER_CA}" \
  || err "chaincode approve failed"

log "Committing chaincode..."
peer lifecycle chaincode commit \
  -o localhost:7050 \
  --channelID ${CHANNEL_NAME} \
  --name ${CHAINCODE_NAME} \
  --version ${CHAINCODE_VERSION} \
  --sequence ${CHAINCODE_SEQUENCE} \
  --tls --cafile "${ORDERER_CA}" \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "${CORE_PEER_TLS_ROOTCERT_FILE}" \
  || err "chaincode commit failed"

log "Chaincode committed. Querying committed chaincodes..."
peer lifecycle chaincode querycommitted \
  --channelID ${CHANNEL_NAME} --name ${CHAINCODE_NAME}

log "\n✅  SecurityLog Fabric network is up and chaincode is deployed."
log "Run: python3 Main.py health"
