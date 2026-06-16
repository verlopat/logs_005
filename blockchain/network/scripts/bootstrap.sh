#!/usr/bin/env bash
# bootstrap.sh — brings up the Hyperledger Fabric network from scratch
# Run from: blockchain/network/
set -e

FABRIC_VERSION="2.5.0"
CA_VERSION="1.5.7"
CHANNEL_NAME="securitylogchannel"
CHAINCODE_NAME="security_logger"
CHAINCODE_VERSION="1.0"
CHAINCODE_PATH="../../chaincode/security_logger"
DELAY=3
MAX_RETRY=5

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

# ── 0. Prerequisites check ────────────────────────────────────────────────────
log "Checking prerequisites..."
for cmd in docker docker-compose peer cryptogen configtxgen; do
  command -v "$cmd" &>/dev/null || err "$cmd not found. Install Hyperledger Fabric binaries first."
done
log "All prerequisites found."

# ── 1. Clean up any previous network ─────────────────────────────────────────
log "Cleaning up previous network artifacts..."
docker-compose -f ../../../docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
rm -rf crypto-config channel-artifacts

mkdir -p channel-artifacts

# ── 2. Generate crypto material ───────────────────────────────────────────────
log "Generating crypto material with cryptogen..."
cryptogen generate --config=./crypto-config.yaml --output="crypto-config" \
  || err "cryptogen failed"
log "Crypto material generated."

# ── 3. Generate genesis block ─────────────────────────────────────────────────
log "Generating genesis block..."
export FABRIC_CFG_PATH=$(pwd)
configtxgen -profile SecurityLogGenesis \
  -channelID system-channel \
  -outputBlock ./channel-artifacts/genesis.block \
  || err "configtxgen genesis block failed"

# ── 4. Generate channel transaction ──────────────────────────────────────────
log "Generating channel transaction..."
configtxgen -profile SecurityLogChannel \
  -outputCreateChannelTx ./channel-artifacts/${CHANNEL_NAME}.tx \
  -channelID ${CHANNEL_NAME} \
  || err "configtxgen channel tx failed"

# ── 5. Generate anchor peer update ────────────────────────────────────────────
log "Generating anchor peer update..."
configtxgen -profile SecurityLogChannel \
  -outputAnchorPeersUpdate ./channel-artifacts/CloudSecOrgMSPanchors.tx \
  -channelID ${CHANNEL_NAME} \
  -asOrg CloudSecOrgMSP \
  || err "configtxgen anchor peer update failed"

# ── 6. Start Docker network ────────────────────────────────────────────────────
log "Starting Fabric Docker network..."
docker-compose -f ../../../docker-compose.yml up -d \
  || err "docker-compose up failed"

log "Waiting ${DELAY}s for containers to start..."
sleep ${DELAY}

# ── 7. Create channel ─────────────────────────────────────────────────────────
log "Creating channel: ${CHANNEL_NAME}..."
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="CloudSecOrgMSP"
export CORE_PEER_MSPCONFIGPATH=$(pwd)/crypto-config/peerOrganizations/cloudsec.securitylog.com/users/Admin@cloudsec.securitylog.com/msp
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE=$(pwd)/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer0.cloudsec.securitylog.com/tls/ca.crt
export ORDERER_CA=$(pwd)/crypto-config/ordererOrganizations/securitylog.com/orderers/orderer.securitylog.com/msp/tlscacerts/tlsca.securitylog.com-cert.pem

peer channel create \
  -o localhost:7050 \
  -c ${CHANNEL_NAME} \
  -f ./channel-artifacts/${CHANNEL_NAME}.tx \
  --outputBlock ./channel-artifacts/${CHANNEL_NAME}.block \
  --tls --cafile ${ORDERER_CA} \
  || err "Channel creation failed"

# ── 8. Join peers to channel ──────────────────────────────────────────────────
for PEER_PORT in 7051 8051; do
  log "Joining peer on port ${PEER_PORT} to channel..."
  export CORE_PEER_ADDRESS=localhost:${PEER_PORT}
  if [ "$PEER_PORT" == "8051" ]; then
    export CORE_PEER_TLS_ROOTCERT_FILE=$(pwd)/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer1.cloudsec.securitylog.com/tls/ca.crt
  fi
  peer channel join -b ./channel-artifacts/${CHANNEL_NAME}.block \
    || err "Peer join failed on port ${PEER_PORT}"
done

# ── 9. Update anchor peers ────────────────────────────────────────────────────
log "Updating anchor peers..."
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE=$(pwd)/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer0.cloudsec.securitylog.com/tls/ca.crt
peer channel update \
  -o localhost:7050 \
  -c ${CHANNEL_NAME} \
  -f ./channel-artifacts/CloudSecOrgMSPanchors.tx \
  --tls --cafile ${ORDERER_CA} \
  || err "Anchor peer update failed"

# ── 10. Package chaincode ──────────────────────────────────────────────────────
log "Packaging chaincode..."
peer lifecycle chaincode package ${CHAINCODE_NAME}.tar.gz \
  --path ${CHAINCODE_PATH} \
  --lang golang \
  --label ${CHAINCODE_NAME}_${CHAINCODE_VERSION} \
  || err "Chaincode packaging failed"

# ── 11. Install chaincode on both peers ───────────────────────────────────────
for PEER_PORT in 7051 8051; do
  log "Installing chaincode on peer:${PEER_PORT}..."
  export CORE_PEER_ADDRESS=localhost:${PEER_PORT}
  if [ "$PEER_PORT" == "8051" ]; then
    export CORE_PEER_TLS_ROOTCERT_FILE=$(pwd)/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer1.cloudsec.securitylog.com/tls/ca.crt
  else
    export CORE_PEER_TLS_ROOTCERT_FILE=$(pwd)/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer0.cloudsec.securitylog.com/tls/ca.crt
  fi
  peer lifecycle chaincode install ${CHAINCODE_NAME}.tar.gz \
    || err "Chaincode install failed on port ${PEER_PORT}"
done

# ── 12. Get package ID ────────────────────────────────────────────────────────
log "Fetching chaincode package ID..."
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE=$(pwd)/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer0.cloudsec.securitylog.com/tls/ca.crt
PACKAGE_ID=$(peer lifecycle chaincode queryinstalled \
  | grep "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" \
  | awk '{print $3}' | tr -d ',')
log "Package ID: ${PACKAGE_ID}"

# ── 13. Approve chaincode for org ─────────────────────────────────────────────
log "Approving chaincode for CloudSecOrg..."
peer lifecycle chaincode approveformyorg \
  -o localhost:7050 \
  --channelID ${CHANNEL_NAME} \
  --name ${CHAINCODE_NAME} \
  --version ${CHAINCODE_VERSION} \
  --package-id ${PACKAGE_ID} \
  --sequence 1 \
  --tls --cafile ${ORDERER_CA} \
  || err "Chaincode approval failed"

# ── 14. Commit chaincode ──────────────────────────────────────────────────────
log "Committing chaincode to channel..."
peer lifecycle chaincode commit \
  -o localhost:7050 \
  --channelID ${CHANNEL_NAME} \
  --name ${CHAINCODE_NAME} \
  --version ${CHAINCODE_VERSION} \
  --sequence 1 \
  --tls --cafile ${ORDERER_CA} \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles $(pwd)/crypto-config/peerOrganizations/cloudsec.securitylog.com/peers/peer0.cloudsec.securitylog.com/tls/ca.crt \
  || err "Chaincode commit failed"

log "✅ Network is UP. Channel: ${CHANNEL_NAME}. Chaincode: ${CHAINCODE_NAME} deployed."
log "Run 'python3 Main.py' from the project root to start the logging service."
