// Local test harness for the Steal the VFY server. Spawns the server on
// 127.0.0.1 with a TEST-ONLY HMAC secret/salt (never a live secret), runs
// checks against it, and exits non-zero on any failure. No external network.
// Usage: node test.js

const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');

const TEST_SECRET = 'test-secret-local-only-do-not-use-live';
const TEST_SALT = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const TEST_PARAMS = '5,50,0,0,0,0,0,0';
const HOLDMODE_PARAMS = '5,50,0,1,0,0,0,0';
const VK = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'circuits', 'vfy-policy_vk.json'), 'utf8'));

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
}

// UUIDv5 (RFC 4122): 8-4-4-4-12 hex, version nibble 5, variant 10xx.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// All six fields the VFY protocol schema requires on a Steal turn response.
function hasSixVfyFields(b) {
  return !!b
    && typeof b.matchId === 'string'
    && typeof b.turn === 'number'
    && typeof b.action === 'object' && b.action !== null
    && typeof b.policyProof === 'object' && b.policyProof !== null
    && typeof b.agentTimestamp === 'string'
    && typeof b.idempotencyKey === 'string';
}

function hmac(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

async function post(port, urlPath, obj, secret) {
  const raw = JSON.stringify(obj);
  const res = await fetch(`http://127.0.0.1:${port}${urlPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(secret ? { 'x-agent-games-signature': hmac(secret, raw) } : {}),
    },
    body: raw,
  });
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* keep null */ }
  return { status: res.status, text, body, sig: res.headers.get('x-agent-games-signature') };
}

async function get(port, urlPath) {
  const res = await fetch(`http://127.0.0.1:${port}${urlPath}`);
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* keep null */ }
  return { status: res.status, text, body };
}

function startServer(port, params) {
  const child = spawn('node', ['server.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      STEAL_STRATEGY_PARAMS: params,
      STEAL_STRATEGY_SALT: TEST_SALT,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => { serverLogs.push(d.toString()); process.stdout.write(`[srv:${port}] ${d}`); });
  child.stderr.on('data', (d) => { serverLogs.push(d.toString()); process.stderr.write(`[srv:${port}:err] ${d}`); });
  return child;
}

// All stdout/stderr from both test servers, for asserting on log lines
// (e.g. the [diag] mismatch diagnostic).
const serverLogs = [];

async function waitHealthy(port, timeoutMs = 30000) {
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await get(port, '/health');
      if (r.status === 200 && r.body && r.body.ok && String(r.body.selfTest || '').startsWith('PASS')) {
        return r.body;
      }
    } catch { /* not up yet */ }
    if (Date.now() - t0 > timeoutMs) throw new Error(`server on :${port} did not become healthy`);
    await new Promise((r) => setTimeout(r, 250));
  }
}

function envelope(matchId, turn, self, opp, commitment, nonce) {
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId,
    turn,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    state: {
      selfBalance: String(self),
      opponentBalance: String(opp),
      selfFortifiedUntilTurn: null,
      opponentFortifiedUntilTurn: null,
    },
    strategyCommitment: { hash: commitment },
    resolverVersion: 'v1',
    nonce,
  };
}

// Local resolver model for the simulated match (documented rules only:
// FORTIFY costs 2 and blocks up to 6 of incoming extraction; EXTRACT takes
// min(amount, opponent balance); both moves resolve simultaneously against
// prior balances). This is a test model, not the platform's resolver.
function resolveTurn(self, opp, ourAction, ourAmount, oppAction, oppAmount) {
  const ourFort = ourAction === 'FORTIFY';
  const oppFort = oppAction === 'FORTIFY';
  let ourGain = 0;
  let oppGain = 0;
  if (ourAction === 'EXTRACT') {
    ourGain = Math.min(ourAmount, opp);
    if (oppFort) ourGain = Math.max(0, ourGain - 6);
  }
  if (oppAction === 'EXTRACT') {
    oppGain = Math.min(oppAmount, self);
    if (ourFort) oppGain = Math.max(0, oppGain - 6);
  }
  const selfNext = self - (ourFort ? 2 : 0) - oppGain + ourGain;
  const oppNext = opp - (oppFort ? 2 : 0) - ourGain + oppGain;
  return [selfNext, oppNext];
}

(async () => {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const P = (arr) => F.toString(poseidon(arr.map((x) => BigInt(x))));
  const matchIdField = (uuid) => BigInt('0x' + uuid.replace(/-/g, '')).toString();

  const srvA = startServer(8790, TEST_PARAMS);
  const srvB = startServer(8791, HOLDMODE_PARAMS);
  try {
    const healthA = await waitHealthy(8790);
    const healthB = await waitHealthy(8791);
    const commitmentA = healthA.commitment;
    const commitmentB = healthB.commitment;
    check('01 servers healthy, self-test PASS', true, `A commitment ${String(commitmentA).slice(0, 18)}…`);

    // Commitment cross-check: Poseidon(params, salt) == /health commitment.
    const expectedCommitA = '0x' + BigInt(P([5n, 50n, 0n, 0n, 0n, 0n, 0n, 0n, BigInt('0x' + TEST_SALT)])).toString(16).padStart(64, '0');
    check('02 /health commitment == Poseidon(params, salt)', String(commitmentA).toLowerCase() === expectedCommitA, expectedCommitA.slice(0, 18) + '…');

    const MID_A = '9f4e1b2a-0000-0000-0000-000000000000';
    const midField = matchIdField(MID_A);

    // 03: valid EXTRACT turn (95/105, default params -> EXTRACT 5).
    let t0 = Date.now();
    let r = await post(8790, '/steal', envelope(MID_A, 3, 95, 105, commitmentA, 'test-nonce-03'), TEST_SECRET);
    const extractMs = Date.now() - t0;
    let proofOk = false;
    let signalsOk = false;
    let hashOk = false;
    if (r.status === 200 && r.body && r.body.policyProof) {
      proofOk = await snarkjs.groth16.verify(VK, r.body.policyProof.public_signals, r.body.policyProof.proof);
      const ps = r.body.policyProof.public_signals;
      const expectedOut = P([BigInt(midField), 3n, 1n]);
      signalsOk = ps.length === 9
        && ps[0] === expectedOut
        && ps[1] === BigInt(commitmentA).toString()
        && ps[2] === midField && ps[3] === '3' && ps[4] === '95' && ps[5] === '105'
        && ps[6] === '2' && ps[7] === '5' && ps[8] === '1';
      // Recompute the guide's publicInputsHash locally.
      const { publicInputsHash } = require('./server.js');
      const wantHash = publicInputsHash(commitmentA, MID_A, 3, '95', '105', 'EXTRACT', 5);
      hashOk = r.body.policyProof.publicInputsHash === wantHash;
    }
    check('03 valid EXTRACT turn -> 200, proof verifies', r.status === 200 && proofOk, `action=${r.body && r.body.action && r.body.action.type} amount=${r.body && r.body.action && r.body.action.amount} round trip ${extractMs}ms`);
    check('04 public signals are output-then-public, as expected', signalsOk, `signals=${r.body && r.body.policyProof && r.body.policyProof.public_signals && r.body.policyProof.public_signals.length}`);
    check('05 publicInputsHash matches the guide construction', hashOk);
    check('06 response is signed', !!r.sig && r.sig === hmac(TEST_SECRET, r.text));

    // 07: FORTIFY case (self 40 < 50) -> FORTIFY, no amount field, proof verifies.
    r = await post(8790, '/steal', envelope(MID_A, 4, 40, 105, commitmentA, 'test-nonce-07'), TEST_SECRET);
    let fortOk = false;
    if (r.status === 200 && r.body && r.body.policyProof) {
      fortOk = await snarkjs.groth16.verify(VK, r.body.policyProof.public_signals, r.body.policyProof.proof);
    }
    check('07 FORTIFY when self < 50, no amount field, proof verifies',
      r.status === 200 && r.body && r.body.action.type === 'FORTIFY' && !('amount' in r.body.action) && fortOk,
      `action=${JSON.stringify(r.body && r.body.action)}`);

    // 08: low-opponent HOLD (opp 0 <= 0) -> HOLD, no amount field, proof verifies.
    r = await post(8790, '/steal', envelope(MID_A, 5, 95, 0, commitmentA, 'test-nonce-08'), TEST_SECRET);
    let holdOk = false;
    if (r.status === 200 && r.body && r.body.policyProof) {
      holdOk = await snarkjs.groth16.verify(VK, r.body.policyProof.public_signals, r.body.policyProof.proof);
    }
    check('08 HOLD when opponent <= 0, no amount field, proof verifies',
      r.status === 200 && r.body && r.body.action.type === 'HOLD' && !('amount' in r.body.action) && holdOk,
      `action=${JSON.stringify(r.body && r.body.action)}`);

    // 09: HOLD-mode server (params[3]=1) -> HOLD.
    r = await post(8791, '/steal', envelope(MID_A, 3, 95, 105, commitmentB, 'test-nonce-09'), TEST_SECRET);
    let holdModeOk = false;
    if (r.status === 200 && r.body && r.body.policyProof) {
      holdModeOk = await snarkjs.groth16.verify(VK, r.body.policyProof.public_signals, r.body.policyProof.proof);
    }
    check('09 HOLD-mode params (p3=1) -> HOLD, proof verifies',
      r.status === 200 && r.body && r.body.action.type === 'HOLD' && holdModeOk);

    // 10: FORTIFY precedence over HOLD-mode (server B, self 40 < 50).
    r = await post(8791, '/steal', envelope(MID_A, 4, 40, 105, commitmentB, 'test-nonce-10'), TEST_SECRET);
    check('10 FORTIFY beats HOLD-mode when self < 50',
      r.status === 200 && r.body && r.body.action.type === 'FORTIFY');

    // 11: bad HMAC -> 401.
    r = await post(8790, '/steal', envelope(MID_A, 6, 95, 105, commitmentA, 'test-nonce-11'), 'wrong-secret');
    check('11 bad HMAC -> 401', r.status === 401);

    // 12: malformed envelope (missing matchId) -> 400.
    const bad = envelope(MID_A, 6, 95, 105, commitmentA, 'test-nonce-12');
    delete bad.matchId;
    r = await post(8790, '/steal', bad, TEST_SECRET);
    check('12 malformed envelope -> 400', r.status === 400);

    // 13: replay same (matchId, turn) -> byte-identical.
    const env13 = envelope(MID_A, 3, 95, 105, commitmentA, 'test-nonce-03');
    const r13a = await post(8790, '/steal', env13, TEST_SECRET);
    const r13b = await post(8790, '/steal', env13, TEST_SECRET);
    check('13 replay same turn -> byte-identical', r13a.text === r13b.text, `identical=${r13a.text === r13b.text}`);

    // 14: commitment mismatch -> HOLD with no proof (200). The HOLD
    // response still carries a valid-UUID idempotencyKey (the platform
    // schema requires it on every response).
    r = await post(8790, '/steal', envelope(MID_A, 7, 95, 105, '0x' + '00'.repeat(32), 'test-nonce-14'), TEST_SECRET);
    check('14 commitment mismatch -> HOLD, no proof',
      r.status === 200 && r.body && r.body.action.type === 'HOLD' && !r.body.policyProof
      && typeof r.body.idempotencyKey === 'string' && UUID_RE.test(r.body.idempotencyKey),
      `reason=${r.body && r.body.reason} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 15: nonce reuse across different turns -> 400.
    const env15a = envelope('aaaaaaaa-0000-0000-0000-000000000000', 1, 100, 100, commitmentA, 'shared-nonce');
    const env15b = envelope('bbbbbbbb-0000-0000-0000-000000000000', 1, 100, 100, commitmentA, 'shared-nonce');
    const r15a = await post(8790, '/steal', env15a, TEST_SECRET);
    const r15b = await post(8790, '/steal', env15b, TEST_SECRET);
    check('15 nonce reuse across turns -> 400', r15a.status === 200 && r15b.status === 400, `first=${r15a.status} second=${r15b.status}`);

    // 16: preflight -> signed {ok:true, protocolVersion:v1}.
    r = await post(8790, '/steal', { type: 'agent-games.preflight.v1' }, TEST_SECRET);
    check('16 preflight -> ok:true, protocolVersion:v1, signed',
      r.status === 200 && r.body && r.body.ok === true && r.body.protocolVersion === 'v1' && !!r.sig);

    // 17: /steal and /agent both accept turns.
    r = await post(8790, '/agent', envelope(MID_A, 8, 95, 105, commitmentA, 'test-nonce-17'), TEST_SECRET);
    check('17 POST /agent also accepts a turn', r.status === 200 && !!r.body.policyProof);

    // 18: full 20-turn simulated match vs a stub opponent (always EXTRACT 5).
    const MID_M = '12345678-0000-0000-0000-000000000000';
    let self = 100;
    let opp = 100;
    let matchOk = true;
    let matchDetail = '';
    let maxMs = 0;
    for (let turn = 1; turn <= 20; turn++) {
      const t1 = Date.now();
      const rr = await post(8790, '/steal', envelope(MID_M, turn, self, opp, commitmentA, `match-nonce-${turn}`), TEST_SECRET);
      const ms = Date.now() - t1;
      maxMs = Math.max(maxMs, ms);
      if (rr.status !== 200 || !rr.body || !rr.body.policyProof) {
        matchOk = false;
        matchDetail = `turn ${turn}: status=${rr.status}, proof=${!!(rr.body && rr.body.policyProof)}`;
        break;
      }
      const v = await snarkjs.groth16.verify(VK, rr.body.policyProof.public_signals, rr.body.policyProof.proof);
      if (!v) { matchOk = false; matchDetail = `turn ${turn}: proof did not verify`; break; }
      if (rr.body.matchId !== MID_M || rr.body.turn !== turn) {
        matchOk = false; matchDetail = `turn ${turn}: echo mismatch`; break;
      }
      const ourAction = rr.body.action.type;
      const ourAmount = rr.body.action.amount || 0;
      // Expected action from the policy, computed independently here.
      let expected = 'EXTRACT';
      if (self < 50) expected = 'FORTIFY';
      else if (opp <= 0) expected = 'HOLD';
      if (ourAction !== expected) {
        matchOk = false; matchDetail = `turn ${turn}: action ${ourAction} != expected ${expected} (self=${self} opp=${opp})`; break;
      }
      if (expected === 'EXTRACT' && ourAmount !== 5) {
        matchOk = false; matchDetail = `turn ${turn}: amount ${ourAmount} != 5`; break;
      }
      const [nextSelf, nextOpp] = resolveTurn(self, opp, ourAction, ourAmount, 'EXTRACT', 5);
      self = nextSelf;
      opp = nextOpp;
    }
    check('18 full 20-turn match: every turn 200 + proof verifies + action as expected',
      matchOk, matchOk ? `final self=${self} opp=${opp}, max turn round trip ${maxMs}ms` : matchDetail);

    // 19: proof-generation time (max turn round trip measured in check 18).
    check('19 max turn round trip is far inside the 5-minute deadline', maxMs < 30000, `max ${maxMs}ms vs 300000ms deadline, ~30s platform push wait`);

    // ---- 18:42 practice fixes: UUID idempotencyKey + tolerant commitment ----
    const MID_F = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';
    async function verifyStealTurn(body) {
      if (!body || !body.policyProof) return false;
      return snarkjs.groth16.verify(VK, body.policyProof.public_signals, body.policyProof.proof);
    }

    // 20: commitment as a bare string -> 200, six VFY fields, proof
    // verifies, idempotencyKey a valid UUID.
    let env20 = envelope(MID_F, 1, 95, 105, commitmentA, 'fix-nonce-20');
    env20.strategyCommitment = commitmentA;
    r = await post(8790, '/steal', env20, TEST_SECRET);
    check('20 commitment bare string -> six VFY fields + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'EXTRACT'
      && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 21: commitment hash without 0x -> FORTIFY, proof verifies.
    let env21 = envelope(MID_F, 2, 40, 105, commitmentA, 'fix-nonce-21');
    env21.strategyCommitment = { hash: commitmentA.replace(/^0x/, '') };
    r = await post(8790, '/steal', env21, TEST_SECRET);
    check('21 commitment hash without 0x -> FORTIFY + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'FORTIFY'
      && !('amount' in r.body.action) && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 22: envelope.commitment as a bare string (no strategyCommitment
    // field) -> HOLD, proof verifies.
    let env22 = envelope(MID_F, 3, 95, 0, commitmentA, 'fix-nonce-22');
    delete env22.strategyCommitment;
    env22.commitment = commitmentA;
    r = await post(8790, '/steal', env22, TEST_SECRET);
    check('22 envelope.commitment bare string -> HOLD + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'HOLD'
      && !('amount' in r.body.action) && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 23: idempotencyKey is a valid UUID and identical on replay of the
    // same turn (replay of check 20's envelope).
    const r23a = await post(8790, '/steal', env20, TEST_SECRET);
    const r23b = await post(8790, '/steal', env20, TEST_SECRET);
    check('23 idempotencyKey UUID + stable across replay',
      r23a.status === 200 && r23b.status === 200 && r23a.text === r23b.text
      && UUID_RE.test(r23a.body.idempotencyKey)
      && r23b.body.idempotencyKey === r23a.body.idempotencyKey,
      `idempotencyKey=${r23a.body && r23a.body.idempotencyKey} replayIdentical=${r23a.text === r23b.text}`);

    // ---- 19:05 practice fix: recursive envelope scan for the commitment ----
    // The 19:05 re-run still failed closed with COMMITMENT_MISMATCH even
    // though the server's commitment is correct and the idempotencyKey
    // UUID fix worked — the live envelope's commitment sits at no fixed
    // path the parser knew. The server now scans the WHOLE envelope
    // recursively for the commitment (hex with/without 0x, decimal
    // string, {hash|commitment|value|digest} object, nested anywhere).
    const MID_S = 'a1b2c3d4-58cc-4372-a567-0e02b2c3d479';
    const commitmentDec = BigInt(commitmentA).toString(); // decimal form

    // 24: commitment nested under input as {strategyCommitment:{hash}}.
    let env24 = envelope(MID_S, 1, 95, 105, commitmentA, 'scan-nonce-24');
    delete env24.strategyCommitment;
    env24.input = { strategyCommitment: { hash: commitmentA } };
    r = await post(8790, '/steal', env24, TEST_SECRET);
    check('24 commitment nested under input as {strategyCommitment:{hash}} -> EXTRACT + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'EXTRACT'
      && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 25: commitment nested under input as a bare string.
    let env25 = envelope(MID_S, 2, 40, 105, commitmentA, 'scan-nonce-25');
    delete env25.strategyCommitment;
    env25.input = { strategyCommitment: commitmentA };
    r = await post(8790, '/steal', env25, TEST_SECRET);
    check('25 commitment nested under input as bare string -> FORTIFY + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'FORTIFY'
      && !('amount' in r.body.action) && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 26: commitment as a decimal string (top-level strategyCommitment).
    let env26 = envelope(MID_S, 3, 95, 105, commitmentA, 'scan-nonce-26');
    env26.strategyCommitment = commitmentDec;
    r = await post(8790, '/steal', env26, TEST_SECRET);
    check('26 commitment as decimal string -> EXTRACT + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'EXTRACT'
      && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 27: strategyCommitment as an object with a .commitment key.
    let env27 = envelope(MID_S, 4, 95, 0, commitmentA, 'scan-nonce-27');
    env27.strategyCommitment = { commitment: commitmentA };
    r = await post(8790, '/steal', env27, TEST_SECRET);
    check('27 strategyCommitment:{commitment} -> HOLD + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'HOLD'
      && !('amount' in r.body.action) && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 28: re-run of the failed 19:05 practice (match 9ca729bc-… turn 1
    // shape) with a fresh matchId and the commitment nested under input
    // -> six VFY fields, proof verifies, UUID stable on replay.
    const MID_T = 'd4e5f6a7-58cc-4372-a567-0e02b2c3d479';
    let env28 = envelope(MID_T, 1, 95, 105, commitmentA, 'scan-nonce-28');
    delete env28.strategyCommitment;
    env28.input = { strategyCommitment: { hash: commitmentA } };
    const r28a = await post(8790, '/steal', env28, TEST_SECRET);
    const r28b = await post(8790, '/steal', env28, TEST_SECRET);
    check('28 re-run of failed 19:05 practice (fresh matchId, commitment nested under input) -> six VFY fields + proof verifies + UUID stable on replay',
      r28a.status === 200 && hasSixVfyFields(r28a.body) && r28a.body.action.type === 'EXTRACT'
      && await verifyStealTurn(r28a.body) && UUID_RE.test(r28a.body.idempotencyKey)
      && r28b.status === 200 && r28b.text === r28a.text,
      `idempotencyKey=${r28a.body && r28a.body.idempotencyKey} replayIdentical=${r28b.text === r28a.text}`);

    // 29: genuinely wrong commitment — a different hex AND a decimal
    // string of a different value -> HOLD, no proof, COMMITMENT_MISMATCH.
    const wrongHex = '0x' + '11'.repeat(32);
    const wrongDec = (BigInt(commitmentA) + 1n).toString();
    let env29a = envelope(MID_S, 5, 95, 105, commitmentA, 'scan-nonce-29a');
    env29a.strategyCommitment = wrongHex;
    const r29a = await post(8790, '/steal', env29a, TEST_SECRET);
    let env29b = envelope(MID_S, 6, 95, 105, commitmentA, 'scan-nonce-29b');
    env29b.strategyCommitment = wrongDec;
    const r29b = await post(8790, '/steal', env29b, TEST_SECRET);
    check('29 wrong commitment (different hex; decimal of a different value) -> HOLD, no proof, COMMITMENT_MISMATCH',
      r29a.status === 200 && r29a.body && r29a.body.action.type === 'HOLD' && !r29a.body.policyProof && r29a.body.reason === 'COMMITMENT_MISMATCH'
      && r29b.status === 200 && r29b.body && r29b.body.action.type === 'HOLD' && !r29b.body.policyProof && r29b.body.reason === 'COMMITMENT_MISMATCH',
      `hexReason=${r29a.body && r29a.body.reason} decReason=${r29b.body && r29b.body.reason}`);

    // 30: the mismatch diagnostic log line prints the envelope's
    // top-level keys and a truncated copy of the body (from the mismatch
    // turns in checks 14 and 29).
    const logs = serverLogs.join('');
    check('30 mismatch diagnostic log line prints envelope keys + truncated body',
      logs.includes('[diag] steal envelope keys=') && logs.includes('strategyCommitment') && logs.includes('matchId')
      && (logs.match(/\[diag\] steal envelope keys=/g) || []).length >= 2,
      `diagLines=${(logs.match(/\[diag\] steal envelope keys=/g) || []).length}`);

    // ---- 19:21 practice fix: left-pad short hex commitments ----
    // The 19:21 re-run still failed closed with COMMITMENT_MISMATCH even
    // though the recursive scanner (check 24–28) finds the commitment in
    // every nested shape — because normaliseCommitment required EXACTLY
    // 64 hex chars. Our commitment starts "0e": rendered by
    // BigInt.toString(16) it arrives as 63 chars "edb7d80…" and was
    // rejected. Short hex is now left-padded to 64 (extra leading zeros
    // are stripped first); digit-only strings keep the decimal path.
    const commitment63 = commitmentA.replace(/^0x0/, ''); // 63 chars, "edb7d80…"
    const wrongHex63 = (BigInt(commitmentA) + 1n).toString(16); // 63 chars, "…431bf"

    // 31: 63-char hex (leading zero nibble dropped) as {hash} -> EXTRACT.
    let env31 = envelope(MID_S, 7, 95, 105, commitmentA, 'pad-nonce-31');
    env31.strategyCommitment = { hash: commitment63 };
    r = await post(8790, '/steal', env31, TEST_SECRET);
    check('31 commitment as 63-char hex (leading zero dropped) -> EXTRACT + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'EXTRACT'
      && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 32: hex with extra leading zeros ("0x000edb7d80…") -> FORTIFY.
    let env32 = envelope(MID_S, 8, 40, 105, commitmentA, 'pad-nonce-32');
    env32.strategyCommitment = { hash: '0x000' + commitment63 };
    r = await post(8790, '/steal', env32, TEST_SECRET);
    check('32 commitment hex with extra leading zeros -> FORTIFY + proof verifies + UUID idempotencyKey',
      r.status === 200 && hasSixVfyFields(r.body) && r.body.action.type === 'FORTIFY'
      && !('amount' in r.body.action) && await verifyStealTurn(r.body) && UUID_RE.test(r.body.idempotencyKey),
      `action=${JSON.stringify(r.body && r.body.action)} idempotencyKey=${r.body && r.body.idempotencyKey}`);

    // 33: re-run of the failed 19:21 practice (match 1948b2bd-… turn 1
    // shape) with a fresh matchId and the commitment as 63-char hex
    // nested under input -> six VFY fields, proof verifies, UUID stable.
    const MID_U = 'e7f8a9b0-33a9-45ba-8fc3-45a3d2225a93';
    let env33 = envelope(MID_U, 1, 95, 105, commitmentA, 'pad-nonce-33');
    delete env33.strategyCommitment;
    env33.input = { strategyCommitment: { hash: commitment63 } };
    const r33a = await post(8790, '/steal', env33, TEST_SECRET);
    const r33b = await post(8790, '/steal', env33, TEST_SECRET);
    check('33 re-run of failed 19:21 practice (fresh matchId, 63-char hex nested under input) -> six VFY fields + proof verifies + UUID stable on replay',
      r33a.status === 200 && hasSixVfyFields(r33a.body) && r33a.body.action.type === 'EXTRACT'
      && await verifyStealTurn(r33a.body) && UUID_RE.test(r33a.body.idempotencyKey)
      && r33b.status === 200 && r33b.text === r33a.text,
      `idempotencyKey=${r33a.body && r33a.body.idempotencyKey} replayIdentical=${r33b.text === r33a.text}`);

    // 34: genuinely wrong commitment as a 63-char hex of a different
    // value -> HOLD, no proof, COMMITMENT_MISMATCH.
    let env34 = envelope(MID_S, 9, 95, 105, commitmentA, 'pad-nonce-34');
    env34.strategyCommitment = { hash: wrongHex63 };
    const r34 = await post(8790, '/steal', env34, TEST_SECRET);
    check('34 wrong commitment as 63-char hex of a different value -> HOLD, no proof, COMMITMENT_MISMATCH',
      r34.status === 200 && r34.body && r34.body.action.type === 'HOLD' && !r34.body.policyProof && r34.body.reason === 'COMMITMENT_MISMATCH',
      `reason=${r34.body && r34.body.reason}`);

    // 35: an envelope with NO commitment anywhere -> HOLD, no proof, and
    // the mismatch diagnostic says explicitly that no candidate was
    // found (distinguishing "absent" from "different").
    let env35 = envelope(MID_S, 10, 95, 105, commitmentA, 'pad-nonce-35');
    delete env35.strategyCommitment;
    const r35 = await post(8790, '/steal', env35, TEST_SECRET);
    const logs35 = serverLogs.join('');
    check('35 envelope with no commitment at all -> HOLD, no proof + [diag] NO commitment candidate line',
      r35.status === 200 && r35.body && r35.body.action.type === 'HOLD' && !r35.body.policyProof && r35.body.reason === 'COMMITMENT_MISMATCH'
      && logs35.includes('[diag] steal envelope: NO commitment candidate found in envelope'),
      `reason=${r35.body && r35.body.reason} noCandidateLine=${logs35.includes('[diag] steal envelope: NO commitment candidate found in envelope')}`);
  } finally {
    srvA.kill();
    srvB.kill();
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  if (failed.length) {
    console.log('FAILED: ' + failed.map((f) => f.name).join('; '));
    process.exit(1);
  }
  process.exit(0);
})().catch((e) => {
  console.error('harness error:', e);
  process.exit(1);
});
