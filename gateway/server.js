/**
 * server.js — Fabric Gateway REST API
 * Exposes Fabric chaincode functions as HTTP endpoints.
 * Python app calls this via requests; no old Python SDK needed.
 *
 * Endpoints:
 *   POST /events                     → LogSecurityEvent
 *   GET  /events/count               → GetEventCount   (must be before /:eventId)
 *   GET  /events/:eventId            → GetEvent
 *   POST /events/:eventId/verify     → VerifyEvent
 *   GET  /history                    → QueryEventHistory  ?assetId=&from=&to=
 *   GET  /health                     → liveness probe
 */

'use strict';

const express  = require('express');
const grpc     = require('@grpc/grpc-js');
const { connect, hash, signers } = require('@hyperledger/fabric-gateway');
const crypto   = require('node:crypto');
const fs       = require('node:fs');
const path     = require('node:path');

const app = express();
app.use(express.json({ limit: '2mb' }));

// ── Config from env ──────────────────────────────────────────────────────────

const CHANNEL     = process.env.FABRIC_CHANNEL    || 'securitylogchannel';
const CHAINCODE   = process.env.FABRIC_CHAINCODE  || 'security_logger';
const MSP_ID      = process.env.FABRIC_MSP_ID     || 'CloudSecOrgMSP';
const PEER_ADDR   = process.env.FABRIC_PEER_ADDR  || 'localhost:7051';
const CRYPTO_BASE = process.env.FABRIC_CRYPTO_BASE
  || path.resolve(__dirname, '../blockchain/network/crypto-config/peerOrganizations/cloudsec.securitylog.com');
const PORT        = parseInt(process.env.GATEWAY_PORT || '3000', 10);

const TLS_CERT    = path.join(CRYPTO_BASE, 'peers/peer0.cloudsec.securitylog.com/tls/ca.crt');
const CLIENT_CERT = path.join(CRYPTO_BASE, 'users/User1@cloudsec.securitylog.com/msp/signcerts/User1@cloudsec.securitylog.com-cert.pem');
// keystore directory may contain a file with any name — find it at runtime
const KEYSTORE_DIR = path.join(CRYPTO_BASE, 'users/User1@cloudsec.securitylog.com/msp/keystore');

function findPrivateKey(dir) {
  const files = fs.readdirSync(dir).filter(f => !f.startsWith('.'));
  if (files.length === 0) throw new Error(`No private key file found in keystore dir: ${dir}`);
  return path.join(dir, files[0]);
}

// ── Gateway singleton ────────────────────────────────────────────────────────

let gateway, contract, grpcClient;

async function connectGateway() {
  const tlsCert    = fs.readFileSync(TLS_CERT);
  const clientCert = fs.readFileSync(CLIENT_CERT).toString();
  const keyPath    = findPrivateKey(KEYSTORE_DIR);
  const privateKey = crypto.createPrivateKey(fs.readFileSync(keyPath));

  console.log(`[Gateway] Using TLS cert:    ${TLS_CERT}`);
  console.log(`[Gateway] Using client cert: ${CLIENT_CERT}`);
  console.log(`[Gateway] Using private key: ${keyPath}`);

  grpcClient = new grpc.Client(
    PEER_ADDR,
    grpc.credentials.createSsl(tlsCert)
  );

  gateway = connect({
    client:              grpcClient,
    identity:            { mspId: MSP_ID, credentials: Buffer.from(clientCert) },
    signer:              signers.newPrivateKeySigner(privateKey),
    hash:                hash.sha256,
    evaluateOptions:     () => ({ deadline: Date.now() + 5000 }),
    endorseOptions:      () => ({ deadline: Date.now() + 15000 }),
    submitOptions:       () => ({ deadline: Date.now() + 5000 }),
    commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
  });

  const network = gateway.getNetwork(CHANNEL);
  contract      = network.getContract(CHAINCODE);
  console.log(`✅  Fabric Gateway connected | peer=${PEER_ADDR} channel=${CHANNEL} chaincode=${CHAINCODE}`);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const decode      = (bytes) => Buffer.from(bytes).toString('utf8');
const parseResult = (bytes) => {
  const str = decode(bytes);
  try { return JSON.parse(str); } catch { return str; }
};

// ── Routes ───────────────────────────────────────────────────────────────────

// Health probe — always first, no async errors possible
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', gateway: !!(gateway && contract), ts: new Date().toISOString() });
});

// GET /events/count — MUST be registered before /events/:eventId
app.get('/events/count', async (req, res, next) => {
  try {
    const { assetId = '' } = req.query;
    const result = await contract.evaluateTransaction('GetEventCount', assetId);
    res.json({ status: 'SUCCESS', result: parseResult(result) });
  } catch (err) { next(err); }
});

// POST /events — LogSecurityEvent
app.post('/events', async (req, res, next) => {
  try {
    const { event_id, event_json, payload_json } = req.body;
    if (!event_id || !event_json || !payload_json)
      return res.status(400).json({ error: 'event_id, event_json, payload_json required' });
    const result = await contract.submitTransaction(
      'LogSecurityEvent', event_id, event_json, payload_json
    );
    res.json({ status: 'SUCCESS', tx_id: event_id, result: decode(result) || null });
  } catch (err) { next(err); }
});

// GET /events/:eventId — GetEvent
app.get('/events/:eventId', async (req, res, next) => {
  try {
    const result = await contract.evaluateTransaction('GetEvent', req.params.eventId);
    res.json({ status: 'SUCCESS', result: parseResult(result) });
  } catch (err) { next(err); }
});

// POST /events/:eventId/verify — VerifyEvent
app.post('/events/:eventId/verify', async (req, res, next) => {
  try {
    const { payload_json } = req.body;
    if (!payload_json)
      return res.status(400).json({ error: 'payload_json required' });
    const result = await contract.evaluateTransaction(
      'VerifyEvent', req.params.eventId, payload_json
    );
    res.json({ status: 'SUCCESS', result: parseResult(result) });
  } catch (err) { next(err); }
});

// GET /history — QueryEventHistory
app.get('/history', async (req, res, next) => {
  try {
    const { assetId = '', from = '', to = '' } = req.query;
    const result = await contract.evaluateTransaction('QueryEventHistory', assetId, from, to);
    res.json({ status: 'SUCCESS', result: parseResult(result) });
  } catch (err) { next(err); }
});

// ── Global error handler ─────────────────────────────────────────────────────

app.use((err, _req, res, _next) => {
  console.error('[Gateway Error]', err?.details || err?.message || err);
  const status = err?.status || 500;
  res.status(status).json({
    error:   err?.message || 'Internal gateway error',
    details: err?.details || undefined,
  });
});

// ── Boot ─────────────────────────────────────────────────────────────────────

(async () => {
  try {
    await connectGateway();
    app.listen(PORT, () => console.log(`🚀 Gateway API listening on http://localhost:${PORT}`));
  } catch (err) {
    console.error('❌  Failed to start Gateway:', err?.message || err);
    process.exit(1);
  }
})();

process.on('SIGTERM', () => { try { gateway?.close(); } catch {} grpcClient?.close(); process.exit(0); });
process.on('SIGINT',  () => { try { gateway?.close(); } catch {} grpcClient?.close(); process.exit(0); });
