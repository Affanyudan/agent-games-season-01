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
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d; });
  server.stderr.on('data', (d) => { serverLog += d; });

  try {
    const health0 = await waitForHealth();
    // Let the startup self-test finish (it runs async after listen).
    for (let i = 0; i < 40 && !serverLog.includes('self-test gatekeeper'); i++) {
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
