# Blockchain-Enabled Tamper-Proof Security Event Logger

This repository implements **Objective 2** of the PhD research project:
a production-style, permissioned blockchain logging architecture for cloud anomaly detection events.

## Architecture

```
Python 3.14 (Main.py)
  └── requests → http://localhost:3000  (Node.js Fabric Gateway REST API)
        └── @hyperledger/fabric-gateway  →  Hyperledger Fabric 2.x Network

IPFS Node (off-chain payload storage)
Prometheus + Grafana (monitoring)
```

**Why REST + Node.js Gateway?**
The old `fabric-sdk-py` is unmaintained and incompatible with Python 3.11+.
The official modern approach is the Fabric Gateway library (Node.js/Go/Java)
exposed as a REST API, called from Python using plain `requests`.

## Requirements

- Python >= 3.11 (tested on 3.14)
- Node.js >= 18
- Go >= 1.21 (for chaincode)
- Docker + Docker Compose
- Hyperledger Fabric binaries: `cryptogen`, `configtxgen`, `peer`
- IPFS Kubo (local node on `:5001`)

## Project Structure

```
.
├── Main.py                          ← python3 Main.py  (runs full pipeline)
├── requirements.txt
├── .env.example
├── docker-compose.yml
├── gateway/                         ← Node.js Fabric Gateway REST API
│   ├── server.js
│   └── package.json
├── blockchain/
│   ├── chaincode/security_logger/   ← Go chaincode
│   ├── network/                     ← crypto-config, configtx, scripts
│   └── sdk/fabric_client.py         ← Python REST client (no old SDK)
├── storage/ipfs_client.py
├── crypto/signer.py
├── api/query_interface.py
├── monitoring/
└── tests/
```

## Setup

```bash
git clone https://github.com/verlopat/logs_005.git && cd logs_005

# Python deps (clean install)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Node.js Gateway deps
cd gateway && npm install && cd ..

# Environment
cp .env.example .env
```

## Run

```bash
# Full pipeline (bootstrap → health → log → verify → history → report)
python3 Main.py
```

Individual commands:
```bash
python3 Main.py bootstrap
python3 Main.py health
python3 Main.py demo-log
python3 Main.py verify <event_id>
python3 Main.py history [asset_id]
python3 Main.py report [ISO27001|SOC2|NIST800-92] [asset_id]
```

Tear down:
```bash
bash blockchain/network/scripts/teardown.sh
```
