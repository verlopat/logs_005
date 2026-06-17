# SecurityLog 005 — Blockchain-Enabled Tamper-Proof Security Event Logger

PhD Objective 2 — Hyperledger Fabric 2.x · IPFS · Python 3.14 · Node.js 18+

## Architecture

```
Python 3.14
  └── Main.py
        ├── crypto/signer.py       (ECDSA / X.509 signing)
        ├── storage/ipfs_client.py (IPFS off-chain payload)
        ├── blockchain/sdk/fabric_client.py  (REST → Node.js Gateway)
        └── api/query_interface.py (audit trail + compliance reports)

Node.js 18  (gateway/server.js)
  └── @hyperledger/fabric-gateway  →  Fabric Peer (gRPC / TLS)

Hyperledger Fabric 2.5
  └── Chaincode: blockchain/chaincode/security_logger  (Go)
```

## Quick Start

### Prerequisites

- Docker + Docker Compose (v1 or v2)
- Node.js ≥ 18 + npm
- Go 1.21+
- Python 3.10+ (3.14 fully supported)
- `curl` (for auto-downloading Fabric binaries)

> **Note:** `cryptogen`, `configtxgen`, and `peer` are **auto-downloaded** by
> `bootstrap.sh` if they are not already in your PATH.

### 1. Clone and set up

```bash
git clone https://github.com/verlopat/logs_005.git
cd logs_005

# Python venv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Node.js Gateway
cd gateway && npm install && cd ..

# Copy environment config
cp .env.example .env
```

### 2. Bootstrap the network

```bash
bash blockchain/network/scripts/bootstrap.sh
```

This will:
1. Auto-download Fabric binaries if missing
2. Generate crypto material (`cryptogen`)
3. Generate genesis block + channel TX (`configtxgen`)
4. Start Docker containers
5. Create channel + join peers
6. Deploy chaincode lifecycle
7. Start the Node.js Gateway API on `http://localhost:3000`

### 3. Run the full pipeline

```bash
source .venv/bin/activate
python3 Main.py
```

### Individual commands

```bash
python3 Main.py bootstrap      # (re-)bootstrap
python3 Main.py health         # check Fabric + IPFS
python3 Main.py demo-log       # log a sample event
python3 Main.py verify <id>    # verify event integrity
python3 Main.py history        # query full audit trail
python3 Main.py report ISO27001  # generate compliance report
```

### 4. Teardown

```bash
bash blockchain/network/scripts/teardown.sh
```

## Project Structure

```
logs_005/
├── Main.py                          # Orchestrator entrypoint
├── requirements.txt                 # Python deps (clean, 5 packages)
├── .env.example                     # Environment config template
├── docker-compose.yml               # Fabric network + IPFS
├── blockchain/
│   ├── chaincode/security_logger/   # Go chaincode
│   ├── network/
│   │   ├── configtx.yaml
│   │   ├── crypto-config.yaml
│   │   └── scripts/
│   │       ├── bootstrap.sh         # Network bring-up
│   │       └── teardown.sh          # Clean shutdown
│   └── sdk/
│       └── fabric_client.py         # Python REST client
├── gateway/
│   ├── server.js                    # Node.js Fabric Gateway API
│   └── package.json
├── crypto/signer.py                 # ECDSA / X.509 event signing
├── storage/ipfs_client.py           # IPFS off-chain storage
├── api/query_interface.py           # Audit trail + compliance reports
└── tests/test_logging.py
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cryptogen: command not found` | Re-run `bootstrap.sh` — it auto-downloads Fabric binaries |
| `gateway: No such file or directory` | Run `cd gateway && npm install` |
| `pip install` fails (externally-managed) | Use venv: `python3 -m venv .venv && source .venv/bin/activate` |
| `pysha3` build error | Old `requirements.txt` — pull latest and reinstall |
| Gateway port 3000 refused | Check `gateway/gateway.log`; re-run bootstrap |
| Private key not found (`priv_sk`) | Fixed in server.js — keystore dir is scanned dynamically |
