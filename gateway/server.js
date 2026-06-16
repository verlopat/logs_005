/**
 * server.js — Fabric Gateway REST API
 * Exposes Fabric chaincode functions as HTTP endpoints.
 * Python app calls this via requests; no old Python SDK needed.
 *
 * Endpoints:
 *   POST /events                     → LogSecurityEvent
 *   GET  /events/:eventId            → GetEvent
 *   POST /events/:eventId/verify     → VerifyEvent
 *   GET  /history                    → QueryEventHistory  ?assetId=&from=&to=
 *   GET  /events/count               → GetEventCount
 *   GET  /health                     → liveness probe
 */

'use strict';

require('express-async-errors');
const express    = require('express');
const grpc       = require('@grpc/grpc-js');
const { connect, hash, signers } = require('@hyperledger/fabric-gateway');
const crypto     = require('node:crypto');
const fs         = require('node:fs');
const path       = require('node:path');

const app  = express();
app.use(express.json({ limit: '2mb' }));

// ── Config from env ─────────────────────────────────────────────────────────

const CHANNEL      = process.env.FABRIC_CHANNEL    || 'securitylogchannel';
const CHAINCODE    = process.env.FABRIC_CHAINCODE  || 'security_logger';
const MSP_ID       = process.env.FABRIC_MSP_ID     || 'CloudSecOrgMSP';
const PEER_ADDR    = process.env.FABRIC_PEER_ADDR  || 'localhost:7051';
const CRYPTO_BASE  = process.env.FABRIC_CRYPTO_BASE
  || '../blockchain/network/crypto-config/peerOrganizations/cloudsec.securitylog.com';
const PORT         = parseInt(process.env.GATEWAY_PORT || '3000', 10);

const TLS_CERT     = path.resolve(CRYPTO_BASE, 'peers/peer0.cloudsec.securitylog.com/tls/ca.crt');
const CLIENT_CERT  = path.resolve(CRYPTO_BASE, 'users/User1@cloudsec.securitylog.com/msp/signcerts/User1@cloudsec.securitylog.com-cert.pem');
const CLIENT_KEY   = path.resolve(CRYPTO_BASE, 'users/User1@cloudsec.securitylog.com/msp/keystore/priv_sk');

// ── Gateway singleton ──────────────────────────────────────────────────────────

let gateway, contract, grpcClient;

async function connectGateway() {
  const tlsCert    = fs.readFileSync(TLS_CERT);
  const clientCert = fs.readFileSync(CLIENT_CERT).toString();
  const privateKey = crypto.createPrivateKey(fs.readFileSync(CLIENT_KEY));

  grpcClient = new grpc.Client(PEER_ADDR, grpc.credentials.createSsl(tlsCert));

  gateway = connect({
    client:           grpcClient,
    identity:         { mspId: MSP_ID, credentials: Buffer.from(clientCert) },
    signer:           signers.newPrivateKeySigner(privateKey),
    hash:             hash.sha256,
    evaluateOptions:  () => ({ deadline: Date.now() + 5000 }),
    endorseOptions:   () => ({ deadline: Date.now() + 15000 }),
    submitOptions:    () => ({ deadline: Date.now() + 5000 }),
    commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
  });

  const network = gateway.getNetwork(CHANNEL);
  contract      = network.getContract(CHAINCODE);
  console.log(`✅  Fabric Gateway connected | peer=${PEER_ADDR} channel=${CHANNEL} chaincode=${CHAINCODE}`);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const decode = (bytes) => Buffer.from(bytes).toString('utf8');
const parseResult = (bytes) => JSON.parse(decode(bytes));

// ── Routes ───────────────────────────────────────────────────────────────────

// Health probe
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', gateway: !!gateway, ts: new Date().toISOString() });
});

// POST /events  — LogSecurityEvent
app.post('/events', async (req, res) => {
  const { event_id, event_json, payload_json } = req.body;
  if (!event_id || !event_json || !payload_json)
    return res.status(400).json({ error: 'event_id, event_json, payload_json required' });

  const result = await contract.submitTransaction(
    'LogSecurityEvent', event_id, event_json, payload_json
  );
  res.json({ status: 'SUCCESS', tx_id: event_id, result: decode(result) || null });
});

// GET /events/:eventId  — GetEvent
app.get('/events/:eventId', async (req, res) => {
  const result = await contract.evaluateTransaction('GetEvent', req.params.eventId);
  res.json({ status: 'SUCCESS', result: parseResult(result) });
});

// POST /events/:eventId/verify  — VerifyEvent
app.post('/events/:eventId/verify', async (req, res) => {
  const { payload_json } = req.body;
  if (!payload_json)
    return res.status(400).json({ error: 'payload_json required' });
  const result = await contract.evaluateTransaction('VerifyEvent', req.params.eventId, payload_json);
  res.json({ status: 'SUCCESS', result: parseResult(result) });
});

// GET /history  — QueryEventHistory
app.get('/history', async (req, res) => {
  const { assetId = '', from = '', to = '' } = req.query;
  const result = await contract.evaluateTransaction('QueryEventHistory', assetId, from, to);
  res.json({ status: 'SUCCESS', result: parseResult(result) });
});

// GET /events/count  — GetEventCount
app.get('/events/count', async (req, res) => {
  const { assetId = '' } = req.query;
  const result = await contract.evaluateTransaction('GetEventCount', assetId);
  res.json({ status: 'SUCCESS', result: parseResult(result) });
});

// ── Error handler ────────────────────────────────────────────────────────────

app.use((err, _req, res, _next) => {
  console.error('[Gateway Error]', err);
  res.status(500).json({ error: err.message || 'Internal gateway error' });
});

// ── Boot ───────────────────────────────────────────────────────────────────

(async () => {
  await connectGateway();
  app.listen(PORT, () => console.log(`🚀 Gateway API listening on http://localhost:${PORT}`));
})();

process.on('SIGTERM', () => { gateway?.close(); grpcClient?.close(); process.exit(0); });
process.on('SIGINT',  () => { gateway?.close(); grpcClient?.close(); process.exit(0); });
