# Fabric Gateway API (Node.js)

This is the thin REST bridge between the Python application and the Hyperledger Fabric network.
It uses the **official `@hyperledger/fabric-gateway`** library (actively maintained, no legacy SDK).

## Requirements

- Node.js >= 18
- Fabric network running (see `blockchain/network/scripts/bootstrap.sh`)

## Setup

```bash
cd gateway
npm install
```

## Start

```bash
# Production
node server.js

# Development (auto-reload)
npm run dev
```

The API listens on `http://localhost:3000` by default.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe |
| `POST` | `/events` | LogSecurityEvent |
| `GET` | `/events/:id` | GetEvent |
| `POST` | `/events/:id/verify` | VerifyEvent |
| `GET` | `/history` | QueryEventHistory |
| `GET` | `/events/count` | GetEventCount |

## Environment Variables

All read from the root `.env` file (or shell env):

```
FABRIC_CHANNEL        default: securitylogchannel
FABRIC_CHAINCODE      default: security_logger
FABRIC_MSP_ID         default: CloudSecOrgMSP
FABRIC_PEER_ADDR      default: localhost:7051
FABRIC_CRYPTO_BASE    path to peerOrganizations/...
GATEWAY_PORT          default: 3000
```
