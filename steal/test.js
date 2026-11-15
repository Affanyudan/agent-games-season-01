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
  child.stdout.on('data', (d) => process.stdout.write(`[srv:${port}] ${d}`));
  child.stderr.on('data', (d) => process.stderr.write(`[srv:${port}:err] ${d}`));
  return child;
}

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

    // 14: commitment mismatch -> HOLD with no proof (200).
    r = await post(8790, '/steal', envelope(MID_A, 7, 95, 105, '0x' + '00'.repeat(32), 'test-nonce-14'), TEST_SECRET);
    check('14 commitment mismatch -> HOLD, no proof',
      r.status === 200 && r.body && r.body.action.type === 'HOLD' && !r.body.policyProof,
      `reason=${r.body && r.body.reason}`);

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
