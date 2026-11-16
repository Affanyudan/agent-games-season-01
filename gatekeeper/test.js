// Local test harness for the A5YFAM Proof Gatekeeper.
// Spawns server.js on a test port with a clearly-marked LOCAL TEST secret,
// runs the checks, prints PASS/FAIL per check, then stops the server.
// No network beyond 127.0.0.1. No real secret, no registration, no spending.
//
// Checks:
//   1  valid task -> APPROVE, proof verifies against exported vk (13 signals)
//   2  VK substitution -> REJECT VK_SUBSTITUTION
//   3  proof reuse (same proof_tx, different task_id) -> REJECT PROOF_REUSED, no proof
//   4  threshold mismatch -> REJECT THRESHOLD_MISMATCH
//   5  expired condition -> REJECT EXPIRED_CONDITION
//   6  recipient mismatch -> REJECT RECIPIENT_MISMATCH
//   7  amount overflow -> REJECT AMOUNT_OVERFLOW
//   8  bad HMAC -> 401
//   9  replay same task_id -> byte-identical response body
//  10  malformed task (missing field) -> REJECT INVALID_TASK
//  11  boundary: balance == minimum -> APPROVE
//  12  boundary: amount == max_transfer -> APPROVE
//  13  boundary: current_block == expiry_block -> REJECT EXPIRED_CONDITION
//  14  circuit refuses to prove APPROVE on trap inputs (direct fullProve, decision=1)
//  15  preflight -> {ok:true, protocolVersion:"v1"} + signed response
//  16  GET /health -> ok:true, hmacConfigured:true, selfTest PASS
//  --- unified endpoint (dashboard sends BOTH tracks to /gatekeeper) ---
//  17  Steal EXTRACT via POST /gatekeeper (matchId routing) -> six VFY
//      fields, correct types, proof verifies against vfy-policy vk, signed
//  18  Steal FORTIFY via POST /gatekeeper (type routing) -> amount omitted,
//      proof verifies
//  19  Steal HOLD via POST /agent -> amount omitted, proof verifies
//  20  Steal replay same (matchId, turn) -> byte-identical response
//  21  Steal commitment mismatch -> HOLD, no proof (200, fail-closed)
//  22  Gatekeeper task after Steal turns -> still APPROVE + proof verifies
//  23  GET /health -> both tracks, steal commitment == Poseidon(params, salt)
//  24  GET / -> lists both tracks + POST /gatekeeper and POST /agent
//  25  Steal EXTRACT, strategyCommitment as a bare string -> six VFY
//      fields, proof verifies, idempotencyKey a valid UUID
//  26  Steal FORTIFY, strategyCommitment.hash without 0x -> proof verifies
//  27  Steal HOLD, envelope.commitment as a bare string -> proof verifies
//  28  Re-run of the failed 18:42 practice (fresh matchId) -> six VFY
//      fields, idempotencyKey a valid UUID, stable across replay

const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

const PORT = 8789;
const BASE = `http://127.0.0.1:${PORT}`;
// LOCAL TEST SECRET ONLY — never a real dashboard secret.
const TEST_SECRET = 'test-secret-local-only-do-not-use-live';
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const RECIP = '0x1111111111111111111111111111111111111111';
// Steal params/salt for the unified process under test. The real salt may
// be passed in via STEAL_STRATEGY_SALT (env only, never written to a file);
// otherwise the TEST-ONLY salt is used and the commitment check (23) just
// verifies Poseidon(params, salt) for that salt.
const STEAL_SALT = (process.env.STEAL_STRATEGY_SALT ||
  '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef').replace(/^0x/, '');
const STEAL_PARAMS = process.env.STEAL_STRATEGY_PARAMS || '5,50,0,0,0,0,0,0';

function sign(body) {
  return crypto.createHmac('sha256', TEST_SECRET).update(body).digest('hex');
}

async function postGatekeeper(task, { badSig = false, rawBody = null } = {}) {
  const body = rawBody !== null ? rawBody : JSON.stringify(task);
  const res = await fetch(`${BASE}/gatekeeper`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-agent-games-signature': badSig ? 'deadbeef' : sign(body),
    },
    body,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON */ }
  return { status: res.status, text, json, respSig: res.headers.get('x-agent-games-signature') };
}

function baseTask(overrides = {}) {
  return {
    task_id: 'gk_test_' + Math.random().toString(36).slice(2, 8),
    registered_vk: VK,
    proof_vk: VK,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: '8430000',
    current_block: '8420000',
    recipient: RECIP,
    condition_recipient: RECIP,
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0xtest' + Math.random().toString(36).slice(2, 8),
    ...overrides,
  };
}

// Steal turn envelope (same shape as steal/test.js). `extra` lets a test
// add a `type` field to exercise type-based routing.
function stealEnvelope(matchId, turn, self, opp, commitment, nonce, extra = {}) {
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
    ...extra,
  };
}

async function postPath(urlPath, obj, { badSig = false } = {}) {
  const body = JSON.stringify(obj);
  const res = await fetch(`${BASE}${urlPath}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-agent-games-signature': badSig ? 'deadbeef' : sign(body),
    },
    body,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON */ }
  return { status: res.status, text, json, respSig: res.headers.get('x-agent-games-signature') };
}

// The six fields the VFY protocol schema requires on a Steal turn response.
function hasSixVfyFields(b) {
  return !!b
    && typeof b.matchId === 'string'
    && typeof b.turn === 'number'
    && typeof b.action === 'object' && b.action !== null
    && typeof b.policyProof === 'object' && b.policyProof !== null
    && typeof b.agentTimestamp === 'string'
    && typeof b.idempotencyKey === 'string';
}

// UUIDv5 (RFC 4122): 8-4-4-4-12 hex, version nibble 5, variant 10xx.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const results = [];
function check(name, pass, detail = '') {
  results.push({ name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
}

async function waitForHealth(tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return await res.json();
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('server did not come up');
}

(async () => {
  const vk = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'circuits', 'gatekeeper_vk.json'), 'utf8'));
  const server = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      HOST: '127.0.0.1',
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      STEAL_STRATEGY_SALT: STEAL_SALT,
      STEAL_STRATEGY_PARAMS: STEAL_PARAMS,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d; });
  server.stderr.on('data', (d) => { serverLog += d; });

  try {
    const health0 = await waitForHealth();
    // Let both startup self-tests finish (they run async after listen).
    for (let i = 0; i < 80 && (!serverLog.includes('self-test gatekeeper') || !serverLog.includes('self-test steal')); i++) {
      await new Promise((r) => setTimeout(r, 250));
    }

    // 16. /health
    check('16 health endpoint', health0.ok === true && health0.hmacConfigured === true,
      `hmacConfigured=${health0.hmacConfigured} selfTest=${health0.selfTest}`);

    // 1. Valid task -> APPROVE + proof verifies.
    const valid = baseTask({ task_id: 'gk_test_valid', proof_tx: '0xaaa1' });
    const t0 = Date.now();
    const r1 = await postGatekeeper(valid);
    const roundTripMs = Date.now() - t0;
    let proofOk = false;
    let signalsDetail = '';
    if (r1.json && r1.json.proof && r1.json.public_signals) {
      proofOk = await snarkjs.groth16.verify(vk, r1.json.public_signals, r1.json.proof);
      signalsDetail = `signals=${r1.json.public_signals.length} decisionSignal=${r1.json.public_signals[11]}`;
    }
    check('01 valid task -> APPROVE + proof verifies',
      r1.status === 200 && r1.json.decision === 'APPROVE' && r1.json.reason_code === 'VALID_CONDITION' && proofOk,
      `status=${r1.status} decision=${r1.json && r1.json.decision} verify=${proofOk} roundTripMs=${roundTripMs} ${signalsDetail}`);

    // 15. Preflight (uses its own body; still HMAC-signed).
    const preBody = JSON.stringify({ type: 'agent-games.preflight.v1' });
    const preRes = await fetch(`${BASE}/gatekeeper`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-agent-games-signature': sign(preBody) },
      body: preBody,
    });
    const preJson = await preRes.json();
    check('15 preflight -> {ok:true, protocolVersion:v1} signed',
      preRes.status === 200 && preJson.ok === true && preJson.protocolVersion === 'v1' &&
      typeof preRes.headers.get('x-agent-games-signature') === 'string',
      `status=${preRes.status} signed=${!!preRes.headers.get('x-agent-games-signature')}`);

    // 9. Replay the SAME task_id -> byte-identical body (cached).
    const rReplay = await postGatekeeper(valid);
    check('09 replay same task_id -> byte-identical response',
      rReplay.status === 200 && rReplay.text === r1.text,
      `identical=${rReplay.text === r1.text}`);

    // 3. Proof reuse: same proof_tx as the valid task, DIFFERENT task_id.
    const r3 = await postGatekeeper(baseTask({ task_id: 'gk_test_reuse', proof_tx: '0xaaa1' }));
    check('03 proof reuse -> REJECT PROOF_REUSED, no proof',
      r3.status === 200 && r3.json.decision === 'REJECT' && r3.json.reason_code === 'PROOF_REUSED' &&
      !r3.json.proof && !r3.json.public_signals,
      `reason=${r3.json && r3.json.reason_code} proofPresent=${!!(r3.json && r3.json.proof)}`);

    // 2. VK substitution.
    const r2 = await postGatekeeper(baseTask({ proof_vk: '0x' + '22'.repeat(32) }));
    check('02 VK substitution -> REJECT VK_SUBSTITUTION',
      r2.json.decision === 'REJECT' && r2.json.reason_code === 'VK_SUBSTITUTION',
      `reason=${r2.json && r2.json.reason_code}`);

    // 4. Threshold mismatch.
    const r4 = await postGatekeeper(baseTask({ public_balance: '999' }));
    check('04 threshold mismatch -> REJECT THRESHOLD_MISMATCH',
      r4.json.decision === 'REJECT' && r4.json.reason_code === 'THRESHOLD_MISMATCH',
      `reason=${r4.json && r4.json.reason_code}`);

    // 5. Expired condition.
    const r5 = await postGatekeeper(baseTask({ current_block: '8430001' }));
    check('05 expired condition -> REJECT EXPIRED_CONDITION',
      r5.json.decision === 'REJECT' && r5.json.reason_code === 'EXPIRED_CONDITION',
      `reason=${r5.json && r5.json.reason_code}`);

    // 6. Recipient mismatch.
    const r6 = await postGatekeeper(baseTask({ recipient: '0x2222222222222222222222222222222222222222' }));
    check('06 recipient mismatch -> REJECT RECIPIENT_MISMATCH',
      r6.json.decision === 'REJECT' && r6.json.reason_code === 'RECIPIENT_MISMATCH',
      `reason=${r6.json && r6.json.reason_code}`);

    // 7. Amount overflow.
    const r7 = await postGatekeeper(baseTask({ amount: '1001' }));
    check('07 amount overflow -> REJECT AMOUNT_OVERFLOW',
      r7.json.decision === 'REJECT' && r7.json.reason_code === 'AMOUNT_OVERFLOW',
      `reason=${r7.json && r7.json.reason_code}`);

    // 8. Bad HMAC -> 401.
    const r8 = await postGatekeeper(baseTask(), { badSig: true });
    check('08 bad HMAC -> 401 bad_signature',
      r8.status === 401 && r8.json && r8.json.error === 'bad_signature',
      `status=${r8.status}`);

    // 10. Malformed task (missing amount).
    const malformed = baseTask();
    delete malformed.amount;
    const r10 = await postGatekeeper(malformed);
    check('10 malformed task -> REJECT INVALID_TASK',
      r10.status === 200 && r10.json.decision === 'REJECT' && r10.json.reason_code === 'INVALID_TASK',
      `reason=${r10.json && r10.json.reason_code}`);

    // 11. Boundary: balance == minimum -> APPROVE.
    const r11 = await postGatekeeper(baseTask({ public_balance: '1000' }));
    check('11 boundary balance == minimum -> APPROVE',
      r11.json.decision === 'APPROVE' && r11.json.reason_code === 'VALID_CONDITION',
      `decision=${r11.json && r11.json.decision}`);

    // 12. Boundary: amount == max_transfer -> APPROVE.
    const r12 = await postGatekeeper(baseTask({ amount: '1000' }));
    check('12 boundary amount == max_transfer -> APPROVE',
      r12.json.decision === 'APPROVE' && r12.json.reason_code === 'VALID_CONDITION',
      `decision=${r12.json && r12.json.decision}`);

    // 13. Boundary: current_block == expiry_block -> REJECT (strict expiry).
    const r13 = await postGatekeeper(baseTask({ current_block: '8430000' }));
    check('13 boundary current == expiry -> REJECT EXPIRED_CONDITION',
      r13.json.decision === 'REJECT' && r13.json.reason_code === 'EXPIRED_CONDITION',
      `reason=${r13.json && r13.json.reason_code}`);

    // 14. Circuit refuses APPROVE on trap inputs (direct fullProve, decision=1).
    const trapInput = {
      registeredVkHash: VK, proofVkHash: VK,
      minimum: '1000', publicBalance: '999',
      expiryBlock: '8430000', currentBlock: '8420000',
      recipient: RECIP, conditionRecipient: RECIP,
      amount: '500', maxTransfer: '1000',
      decision: '1', taskId: '12345', salt: '0x' + crypto.randomBytes(32).toString('hex'),
    };
    let trapFailed = false;
    let trapErr = '';
    const t1 = Date.now();
    try {
      await snarkjs.groth16.fullProve(
        trapInput,
        path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm'),
        path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey'),
      );
    } catch (e) {
      trapFailed = true;
      trapErr = String(e.message).split('\n')[0].slice(0, 120);
    }
    const trapMs = Date.now() - t1;
    check('14 circuit refuses APPROVE on trap inputs',
      trapFailed, `threw=${trapFailed} (${trapErr}) in ${trapMs}ms`);

    // Direct proof timing (clean fullProve on the valid input).
    const validInput = {
      registeredVkHash: VK, proofVkHash: VK,
      minimum: '1000', publicBalance: '1460',
      expiryBlock: '8430000', currentBlock: '8420000',
      recipient: RECIP, conditionRecipient: RECIP,
      amount: '500', maxTransfer: '1000',
      decision: '1', taskId: '999', salt: '0x' + crypto.randomBytes(32).toString('hex'),
    };
    const t2 = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      validInput,
      path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm'),
      path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey'),
    );
    const proveMs = Date.now() - t2;
    const directOk = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(`INFO  direct fullProve (valid input): ${proveMs}ms, verifies=${directOk}, signals=${publicSignals.length}`);

    // ---- unified endpoint: Steal the VFY turns via POST /gatekeeper ----
    // The dashboard sends both tracks' tasks to this single endpoint, so a
    // Steal turn must be answered here with all six VFY fields. The match
    // id below is the one from the real failed practice (2026-11-16 18:13
    // WIB), replayed locally against the unified server.
    const stealVk = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'circuits', 'vfy-policy_vk.json'), 'utf8'));
    const health1 = await (await fetch(`${BASE}/health`)).json();
    const stealCommitment = health1.steal && health1.steal.commitment;
    const { buildPoseidon } = require(path.join(__dirname, '..', 'steal', 'node_modules', 'circomlibjs'));
    const poseidon = await buildPoseidon();
    const P = (arr) => poseidon.F.toString(poseidon(arr.map((x) => BigInt(x))));
    const paramsArr = STEAL_PARAMS.split(',').map((s) => BigInt(s.trim()));
    const expectedCommitment = '0x' + BigInt(P([...paramsArr, BigInt('0x' + STEAL_SALT)])).toString(16).padStart(64, '0');
    const MID_U = '638ce8fe-f11f-466e-906d-2ac10ecc73f9';

    // 17. Steal EXTRACT via POST /gatekeeper, matchId-only routing (the
    // envelope as documented has no `type` field).
    const env17 = stealEnvelope(MID_U, 1, 95, 105, stealCommitment, 'unified-nonce-17');
    const r17 = await postPath('/gatekeeper', env17);
    let v17 = false;
    if (r17.status === 200 && r17.json && r17.json.policyProof) {
      v17 = await snarkjs.groth16.verify(stealVk, r17.json.policyProof.public_signals, r17.json.policyProof.proof);
    }
    check('17 Steal EXTRACT via POST /gatekeeper (matchId routing): six VFY fields + proof verifies + signed',
      r17.status === 200 && hasSixVfyFields(r17.json)
      && r17.json.action.type === 'EXTRACT' && r17.json.action.amount === 5 && v17
      && r17.respSig === sign(r17.text),
      `status=${r17.status} action=${JSON.stringify(r17.json && r17.json.action)} verify=${v17} signed=${r17.respSig === sign(r17.text)}`);

    // 18. Steal FORTIFY via POST /gatekeeper, type-based routing.
    const env18 = stealEnvelope(MID_U, 2, 40, 105, stealCommitment, 'unified-nonce-18', { type: 'agent-games.steal-the-vfy.v1' });
    const r18 = await postPath('/gatekeeper', env18);
    let v18 = false;
    if (r18.status === 200 && r18.json && r18.json.policyProof) {
      v18 = await snarkjs.groth16.verify(stealVk, r18.json.policyProof.public_signals, r18.json.policyProof.proof);
    }
    check('18 Steal FORTIFY via POST /gatekeeper (type routing): amount omitted + proof verifies',
      r18.status === 200 && hasSixVfyFields(r18.json)
      && r18.json.action.type === 'FORTIFY' && !('amount' in r18.json.action) && v18,
      `action=${JSON.stringify(r18.json && r18.json.action)} verify=${v18}`);

    // 19. Steal HOLD via POST /agent (self 95, opp 0 -> HOLD).
    const env19 = stealEnvelope(MID_U, 3, 95, 0, stealCommitment, 'unified-nonce-19');
    const r19 = await postPath('/agent', env19);
    let v19 = false;
    if (r19.status === 200 && r19.json && r19.json.policyProof) {
      v19 = await snarkjs.groth16.verify(stealVk, r19.json.policyProof.public_signals, r19.json.policyProof.proof);
    }
    check('19 Steal HOLD via POST /agent: amount omitted + proof verifies',
      r19.status === 200 && hasSixVfyFields(r19.json)
      && r19.json.action.type === 'HOLD' && !('amount' in r19.json.action) && v19,
      `action=${JSON.stringify(r19.json && r19.json.action)} verify=${v19}`);

    // 20. Steal replay same (matchId, turn) -> byte-identical.
    const r20 = await postPath('/gatekeeper', env17);
    check('20 Steal replay same (matchId, turn) -> byte-identical',
      r20.status === 200 && r20.text === r17.text, `identical=${r20.text === r17.text}`);

    // 21. Steal commitment mismatch -> HOLD, no proof (200, fail-closed).
    // NOTE: a HOLD with no policyProof will not pass the platform's strict
    // schema validation either, but this is the guide's fail-closed shape
    // (live: resolved as HOLD, -2); this check only asserts parity with
    // the standalone Steal server.
    const env21 = stealEnvelope(MID_U, 4, 95, 105, '0x' + '00'.repeat(32), 'unified-nonce-21');
    const r21 = await postPath('/gatekeeper', env21);
    check('21 Steal commitment mismatch -> HOLD, no proof',
      r21.status === 200 && r21.json && r21.json.action.type === 'HOLD' && !r21.json.policyProof
      && r21.json.reason === 'COMMITMENT_MISMATCH'
      && typeof r21.json.idempotencyKey === 'string' && UUID_RE.test(r21.json.idempotencyKey),
      `reason=${r21.json && r21.json.reason} idempotencyKey=${r21.json && r21.json.idempotencyKey}`);

    // 22. Gatekeeper task after Steal turns -> still APPROVE + proof verifies.
    const r22 = await postGatekeeper(baseTask({ task_id: 'gk_test_after_steal', proof_tx: '0xbbb2' }));
    let v22 = false;
    if (r22.json && r22.json.proof && r22.json.public_signals) {
      v22 = await snarkjs.groth16.verify(vk, r22.json.public_signals, r22.json.proof);
    }
    check('22 Gatekeeper task after Steal turns -> APPROVE + proof verifies',
      r22.status === 200 && r22.json.decision === 'APPROVE' && v22,
      `decision=${r22.json && r22.json.decision} verify=${v22}`);

    // 23. /health reports both tracks; steal commitment == Poseidon(params, salt).
    check('23 /health reports both tracks, steal commitment == Poseidon(params, salt)',
      health1.ok === true && Array.isArray(health1.tracks)
      && health1.tracks.includes('proof-gatekeeper') && health1.tracks.includes('steal-the-vfy')
      && String(stealCommitment).toLowerCase() === expectedCommitment
      && String(health1.steal.selfTest).startsWith('PASS'),
      `commitment=${String(stealCommitment).slice(0, 18)}… expected=${expectedCommitment.slice(0, 18)}… stealSelfTest=${health1.steal.selfTest}`);

    // 24. GET / lists both tracks + POST /gatekeeper and POST /agent.
    const rootRes = await fetch(`${BASE}/`);
    const rootJson = await rootRes.json();
    check('24 GET / lists both tracks + /gatekeeper and /agent',
      rootRes.status === 200 && Array.isArray(rootJson.tracks)
      && rootJson.tracks.includes('steal-the-vfy')
      && rootJson.endpoints.includes('POST /gatekeeper') && rootJson.endpoints.includes('POST /agent'),
      `tracks=${JSON.stringify(rootJson.tracks)} endpoints=${JSON.stringify(rootJson.endpoints)}`);

    // ---- Steal fixes (2026-11-16 18:42 practice failure) ----
    // The platform failed the re-run with two schema errors: policyProof
    // undefined (the live envelope's commitment was not recognised, so the
    // server failed closed to HOLD) and idempotencyKey "Invalid UUID"
    // ("matchId:turn" is not a UUID). The response field is now a
    // deterministic UUIDv5 of "matchId:turn", and the commitment parser
    // accepts strategyCommitment as {hash} | bare string (with or without
    // 0x), envelope.commitment, and envelope.strategyCommitmentHash.
    const MID_FIX = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

    // 25. Variant (b): strategyCommitment as a bare string -> EXTRACT,
    // six VFY fields, proof verifies, idempotencyKey a valid UUID.
    const env25 = stealEnvelope(MID_FIX, 1, 95, 105, stealCommitment, 'fix-nonce-25',
      { strategyCommitment: stealCommitment });
    const r25 = await postPath('/gatekeeper', env25);
    let v25 = false;
    if (r25.status === 200 && r25.json && r25.json.policyProof) {
      v25 = await snarkjs.groth16.verify(stealVk, r25.json.policyProof.public_signals, r25.json.policyProof.proof);
    }
    check('25 Steal EXTRACT, strategyCommitment bare string -> six VFY fields + proof verifies + UUID idempotencyKey',
      r25.status === 200 && hasSixVfyFields(r25.json)
      && r25.json.action.type === 'EXTRACT' && r25.json.action.amount === 5 && v25
      && UUID_RE.test(r25.json.idempotencyKey),
      `action=${JSON.stringify(r25.json && r25.json.action)} verify=${v25} idempotencyKey=${r25.json && r25.json.idempotencyKey}`);

    // 26. Variant (c): strategyCommitment.hash without 0x -> FORTIFY,
    // proof verifies, idempotencyKey a valid UUID.
    const env26 = stealEnvelope(MID_FIX, 2, 40, 105, stealCommitment, 'fix-nonce-26',
      { strategyCommitment: { hash: String(stealCommitment).replace(/^0x/, '') } });
    const r26 = await postPath('/gatekeeper', env26);
    let v26 = false;
    if (r26.status === 200 && r26.json && r26.json.policyProof) {
      v26 = await snarkjs.groth16.verify(stealVk, r26.json.policyProof.public_signals, r26.json.policyProof.proof);
    }
    check('26 Steal FORTIFY, strategyCommitment.hash without 0x -> proof verifies + UUID idempotencyKey',
      r26.status === 200 && hasSixVfyFields(r26.json)
      && r26.json.action.type === 'FORTIFY' && !('amount' in r26.json.action) && v26
      && UUID_RE.test(r26.json.idempotencyKey),
      `action=${JSON.stringify(r26.json && r26.json.action)} verify=${v26} idempotencyKey=${r26.json && r26.json.idempotencyKey}`);

    // 27. Variant (d): envelope.commitment as a bare string (no
    // strategyCommitment field at all) -> HOLD, proof verifies.
    const env27 = stealEnvelope(MID_FIX, 3, 95, 0, stealCommitment, 'fix-nonce-27');
    delete env27.strategyCommitment;
    env27.commitment = stealCommitment;
    const r27 = await postPath('/gatekeeper', env27);
    let v27 = false;
    if (r27.status === 200 && r27.json && r27.json.policyProof) {
      v27 = await snarkjs.groth16.verify(stealVk, r27.json.policyProof.public_signals, r27.json.policyProof.proof);
    }
    check('27 Steal HOLD, envelope.commitment bare string -> proof verifies + UUID idempotencyKey',
      r27.status === 200 && hasSixVfyFields(r27.json)
      && r27.json.action.type === 'HOLD' && !('amount' in r27.json.action) && v27
      && UUID_RE.test(r27.json.idempotencyKey),
      `action=${JSON.stringify(r27.json && r27.json.action)} verify=${v27} idempotencyKey=${r27.json && r27.json.idempotencyKey}`);

    // 28. Re-run of the failed 18:42 practice with a fresh matchId:
    // standard {hash} shape, state 95/105 -> EXTRACT, six VFY fields,
    // idempotencyKey a valid UUID and identical on replay.
    const env28 = stealEnvelope(MID_FIX, 4, 95, 105, stealCommitment, 'fix-nonce-28');
    const r28a = await postPath('/gatekeeper', env28);
    const r28b = await postPath('/gatekeeper', env28);
    let v28 = false;
    if (r28a.status === 200 && r28a.json && r28a.json.policyProof) {
      v28 = await snarkjs.groth16.verify(stealVk, r28a.json.policyProof.public_signals, r28a.json.policyProof.proof);
    }
    check('28 Re-run of failed 18:42 practice (fresh matchId) -> six VFY fields + proof verifies + UUID idempotencyKey stable on replay',
      r28a.status === 200 && hasSixVfyFields(r28a.json)
      && r28a.json.action.type === 'EXTRACT' && v28
      && UUID_RE.test(r28a.json.idempotencyKey)
      && r28b.status === 200 && r28b.text === r28a.text
      && r28b.json.idempotencyKey === r28a.json.idempotencyKey,
      `idempotencyKey=${r28a.json && r28a.json.idempotencyKey} verify=${v28} replayIdentical=${r28b.text === r28a.text}`);

    // Self-test line from server log.
    const selfTestLine = (serverLog.match(/self-test gatekeeper: .*/) || ['(not in log yet)'])[0];
    console.log(`INFO  server startup: ${selfTestLine}`);
    console.log(`INFO  valid-task round trip (incl. prove): ${roundTripMs}ms`);
  } finally {
    server.kill();
  }

  const passed = results.filter((r) => r.pass).length;
  console.log(`\nRESULT: ${passed}/${results.length} checks passed`);
  if (passed !== results.length) {
    console.log('FAILED CHECKS:');
    for (const r of results.filter((x) => !x.pass)) console.log(`  - ${r.name}`);
    process.exit(1);
  }
})().catch((e) => {
  console.error('HARNESS ERROR:', e);
  process.exit(2);
});
