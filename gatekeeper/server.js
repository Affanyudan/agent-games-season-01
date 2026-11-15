// A5YFAM — Proof Gatekeeper for zkVerify Agent Games Season 01.
// Single Node.js file, stdlib http + crypto only (plus snarkjs for Groth16).
//
// Protocol (from the official Builder Field Guide, agentgames.zkverify.io/build,
// and /api/circuit-info; cross-checked against two independent public
// reference builds that ran the same circuit locally):
//   POST /gatekeeper — signed JSON task envelope. Verify the HMAC-SHA256
//     signature in header `x-agent-games-signature` over the RAW body BEFORE
//     parsing anything. Bad signature -> 401, no work done.
//   Preflight {"type":"agent-games.preflight.v1"} -> {ok:true, protocolVersion:"v1"}.
//   Task fields (inside `input` or top-level): registered_vk, proof_vk,
//     minimum, public_balance, expiry_block, current_block, recipient,
//     condition_recipient, amount, max_transfer, plus proof_tx and task_id.
//   Decision rules (first failing check wins, fail closed):
//     VK_SUBSTITUTION   proof_vk != registered_vk
//     PROOF_REUSED      proof_tx already seen under a DIFFERENT task_id
//     THRESHOLD_MISMATCH public_balance < minimum   (== minimum is VALID)
//     EXPIRED_CONDITION current_block >= expiry_block (expiry is STRICT)
//     RECIPIENT_MISMATCH recipient != condition_recipient (case-insensitive)
//     AMOUNT_OVERFLOW   amount > max_transfer       (== max is VALID)
//     else VALID_CONDITION -> APPROVE
//   Every decision (except PROOF_REUSED) is proven with the official
//   gatekeeper circuit (Groth16/BN128, Circom 2.x) via snarkjs 0.7.6:
//   decision 1 = APPROVE, 0 = REJECT; 13 public signals.
//   Response: {decision, reason_code, proof_tx, proof, public_signals}.
//   Responses are signed with x-agent-games-signature over the raw body.
//   Retries of the same task_id return the byte-identical cached response.
//   GET /health — readiness (HMAC configured? self-test?).
//   60-second hard deadline: proof takes ~1s locally; a 45s internal guard
//   fails closed to REJECT if proving ever stalls.
//   If proof generation fails on an APPROVE, fail closed to REJECT
//   (reason PROOF_FAILED) instead of returning an unprovable approval.
//
// Secrets: the HMAC secret comes ONLY from AGENT_GAMES_HMAC_SECRET.
// The dashboard-issued secret is required before going live; without it,
// inbound verification is disabled and /health says so. No wallet keys,
// no signing, no spending anywhere in this server.
//
// Env vars:
//   PORT (default 8787), HOST (default 127.0.0.1)
//   AGENT_GAMES_HMAC_SECRET — dashboard secret (required for live)
//   AGENT_GAMES_HMAC_FORMAT — 'hex' (default) or 'sha256='
//   GATEKEEPER_TASK_ID_MODE — 'keccak' (default), 'numeric', 'hex'
//     How the string task_id maps to a circuit field element. The keccak
//     default is UNCONFIRMED against the platform: if a practice task's
//     proof is rejected, switch the mode and retry (no other code changes).

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { keccak256ModP, FIELD_PRIME } = require('./keccak');

const AGENT_NAME = 'A5YFAM';
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const HMAC_SECRET = (process.env.AGENT_GAMES_HMAC_SECRET || '').trim();
const HMAC_FORMAT = (process.env.AGENT_GAMES_HMAC_FORMAT || 'hex').trim();
const TASK_ID_MODE = (process.env.GATEKEEPER_TASK_ID_MODE || 'keccak').trim();
const REGISTERED_VK =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = path.join(__dirname, '..', 'circuits', 'gatekeeper_vk.json');

// ---- HMAC (header x-agent-games-signature) ----
function signatureFor(secret, rawBody, format) {
  const hex = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

function verifySignature(secret, rawBody, sig, format) {
  if (typeof sig !== 'string' || !sig) return false;
  const expected = signatureFor(secret, rawBody, format);
  const a = Buffer.from(sig, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ---- task_id -> field element ----
function taskIdToField(taskId, mode) {
  const id = String(taskId || '');
  if (mode === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? BigInt(digits) % FIELD_PRIME : 0n;
  }
  if (mode === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? BigInt('0x' + hex) % FIELD_PRIME : 0n;
  }
  return keccak256ModP([Buffer.from(id, 'utf8')]); // default: keccak256 mod p
}

// ---- decision logic (must match the circuit's checks exactly) ----
const REQUIRED_FIELDS = [
  'registered_vk', 'proof_vk', 'minimum', 'public_balance',
  'expiry_block', 'current_block', 'recipient', 'condition_recipient',
  'amount', 'max_transfer',
];

const seenProofTx = new Map(); // proof_tx (lowercased) -> task_id
const responseCache = new Map(); // task_id -> { status, body }

function decide(task) {
  const registeredVk = String(task.registered_vk || '').toLowerCase();
  const proofVk = String(task.proof_vk || '').toLowerCase();
  let minimum, publicBalance, expiryBlock, currentBlock, amount, maxTransfer;
  try {
    minimum = BigInt(task.minimum);
    publicBalance = BigInt(task.public_balance);
    expiryBlock = BigInt(task.expiry_block);
    currentBlock = BigInt(task.current_block);
    amount = BigInt(task.amount);
    maxTransfer = BigInt(task.max_transfer);
  } catch {
    return { decision: 'REJECT', reason_code: 'INVALID_TASK' };
  }
  const recipient = String(task.recipient || '').toLowerCase();
  const conditionRecipient = String(task.condition_recipient || '').toLowerCase();
  const proofTx = String(task.proof_tx || '').toLowerCase();
  const taskId = String(task.task_id || '');

  if (proofVk !== registeredVk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };

  if (proofTx) {
    const prevTask = seenProofTx.get(proofTx);
    if (prevTask !== undefined && prevTask !== taskId) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    if (prevTask === undefined) seenProofTx.set(proofTx, taskId);
  }

  if (publicBalance < minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (currentBlock >= expiryBlock) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (recipient !== conditionRecipient) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (amount > maxTransfer) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// ---- proving ----
function buildCircuitInput(task, decision) {
  return {
    registeredVkHash: String(task.registered_vk),
    proofVkHash: String(task.proof_vk),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: String(task.recipient),
    conditionRecipient: String(task.condition_recipient),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id, TASK_ID_MODE).toString(),
    salt: '0x' + crypto.randomBytes(32).toString('hex'),
  };
}

async function proveTask(task, decision) {
  const input = buildCircuitInput(task, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('proof timeout after ' + ms + 'ms')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ---- HTTP helpers ----
function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body, HMAC_FORMAT);
  res.writeHead(status, headers);
  res.end(body);
}

function sendCached(res, cached) {
  const headers = { 'Content-Type': 'application/json' };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, cached.body, HMAC_FORMAT);
  res.writeHead(cached.status, headers);
  res.end(cached.body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---- Gatekeeper handler ----
async function handleGatekeeper(obj) {
  const task = obj.input || obj;
  const taskId = String(task.task_id || '');
  if (taskId && responseCache.has(taskId)) {
    return { cached: responseCache.get(taskId) };
  }

  for (const f of REQUIRED_FIELDS) {
    if (task[f] === undefined || task[f] === null || task[f] === '') {
      const body = { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: String(task.proof_tx || '') };
      if (taskId) responseCache.set(taskId, { status: 200, body: JSON.stringify(body) });
      return { status: 200, body };
    }
  }

  let { decision, reason_code } = decide(task);
  const proofTx = String(task.proof_tx || '');

  if (reason_code === 'PROOF_REUSED') {
    // No proof to submit for a reused proof.
    const body = { decision, reason_code, proof_tx: proofTx };
    if (taskId) responseCache.set(taskId, { status: 200, body: JSON.stringify(body) });
    return { status: 200, body };
  }

  try {
    const { proof, publicSignals } = await withTimeout(proveTask(task, decision), 45000);
    const body = { decision, reason_code, proof_tx: proofTx, proof, public_signals: publicSignals };
    if (taskId) responseCache.set(taskId, { status: 200, body: JSON.stringify(body) });
    return { status: 200, body };
  } catch (e) {
    console.error('[gatekeeper] proof failed:', e.message);
    if (decision === 'APPROVE') {
      // Fail closed: never return an approval we cannot prove.
      decision = 'REJECT';
      reason_code = 'PROOF_FAILED';
    }
    const body = { decision, reason_code, proof_tx: proofTx };
    if (taskId) responseCache.set(taskId, { status: 200, body: JSON.stringify(body) });
    return { status: 200, body };
  }
}

// ---- startup self-test (sample scenario from the field guide) ----
let gatekeeperSelfTest = 'pending';

async function selfTest() {
  try {
    const task = {
      task_id: 'gk_selftest_1',
      registered_vk: REGISTERED_VK,
      proof_vk: REGISTERED_VK,
      minimum: '1000', public_balance: '1460',
      expiry_block: '8430000', current_block: '8420000',
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500', max_transfer: '1000', proof_tx: '0xselftest',
    };
    const { decision } = decide(task);
    const { proof, publicSignals } = await proveTask(task, decision);
    const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    gatekeeperSelfTest = ok && decision === 'APPROVE'
      ? 'PASS (APPROVE proof verifies locally)'
      : 'FAIL';
  } catch (e) {
    gatekeeperSelfTest = 'FAIL: ' + e.message;
  }
}

// ---- HTTP server ----
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, {
        ok: true,
        agent: AGENT_NAME,
        track: 'proof-gatekeeper',
        hmacConfigured: !!HMAC_SECRET,
        taskIdMode: TASK_ID_MODE,
        selfTest: gatekeeperSelfTest,
        uptimeSec: Math.floor(process.uptime()),
      });
    }

    if (req.method === 'GET' && req.url === '/') {
      return sendJson(res, 200, {
        service: 'agent-games',
        agent: AGENT_NAME,
        tracks: ['proof-gatekeeper'],
        endpoints: ['POST /gatekeeper', 'GET /health'],
      });
    }

    if (req.method !== 'POST' || req.url !== '/gatekeeper') {
      return sendJson(res, 404, { error: 'not found' });
    }

    const rawBody = await readBody(req);

    if (HMAC_SECRET) {
      const sig = req.headers['x-agent-games-signature'];
      if (!verifySignature(HMAC_SECRET, rawBody, sig, HMAC_FORMAT)) {
        console.warn('[warn] HMAC mismatch on /gatekeeper');
        return sendJson(res, 401, { error: 'bad_signature' });
      }
    } else {
      console.warn('[warn] AGENT_GAMES_HMAC_SECRET is not set — inbound HMAC is NOT verified. Set it before going live.');
    }

    let obj;
    try {
      obj = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid JSON' });
    }

    if (obj && obj.type === 'agent-games.preflight.v1') {
      return sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, true);
    }

    const result = await handleGatekeeper(obj);
    if (result.cached) return sendCached(res, result.cached);
    return sendJson(res, result.status, result.body, true);
  } catch (e) {
    console.error('[server] unhandled error:', e);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, HOST, async () => {
  console.log(`[server] ${AGENT_NAME} gatekeeper listening on ${HOST}:${PORT}`);
  console.log(`[server] HMAC secret: ${HMAC_SECRET ? 'configured' : 'NOT SET (inbound verification disabled)'}`);
  console.log(`[server] taskIdMode: ${TASK_ID_MODE}`);
  await selfTest();
  console.log(`[server] self-test gatekeeper: ${gatekeeperSelfTest}`);
});

module.exports = { server, decide, taskIdToField };
