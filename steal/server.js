// A5YFAM — Steal the VFY for zkVerify Agent Games Season 01.
// Single Node.js file, stdlib http + crypto only (plus snarkjs for Groth16
// and circomlibjs for Poseidon).
//
// Protocol (from the official Builder Field Guide, agentgames.zkverify.io/build,
// the /events/steal-the-vfy page, /api/circuit-info, and /rules):
//   POST /steal (the guide's example path is POST /agent; both are accepted)
//   — signed turn envelope. Verify the HMAC-SHA256 signature in header
//     `x-agent-games-signature` over the RAW body BEFORE parsing anything.
//     Bad signature -> 401, no work done.
//   Turn envelope: {protocolVersion, eventId:"steal-the-vfy", mode,
//     matchId (UUID), turn, issuedAt, deadlineAt,
//     state:{selfBalance, opponentBalance, selfFortifiedUntilTurn,
//            opponentFortifiedUntilTurn},
//     strategyCommitment:{hash}, resolverVersion, nonce}.
//     The commitment is accepted in several shapes (the platform's live
//     envelope does not always use strategyCommitment:{hash} — the 18:42,
//     19:05 and 19:21 practice runs failed closed with COMMITMENT_MISMATCH
//     even though the server's commitment is correct): a bare string,
//     {hash} with or without the 0x prefix (case-insensitive), a hex
//     value with leading zero nibbles dropped (e.g. 63 chars "edb7d80…"
//     from BigInt.toString(16) — left-padded back to 64) or with extra
//     leading zeros, envelope.commitment (string or {hash}),
//     envelope.strategyCommitmentHash, strategyCommitment as an object
//     with any of the keys hash / commitment / value / digest, a
//     decimal-digit string of the field element, or the commitment
//     nested anywhere in the envelope (the whole envelope is scanned
//     recursively for it). See envelopeCommitment() /
//     scanEnvelopeCommitment(). On a genuine mismatch the server logs a
//     [diag] line with the envelope's top-level keys and a
//     string-truncated copy of the body, so the shape can be diagnosed
//     from live logs.
//   5-minute turn deadline (the platform waits ~30 s per push).
//   Response: {matchId, turn, action:{type, amount?},
//     policyProof:{circuitVersion:"v1", proof, public_signals,
//                  proofReference?, publicInputsHash?},
//     agentTimestamp, idempotencyKey}.
//   idempotencyKey is a deterministic UUIDv5 (nil-UUID namespace) of the
//   internal cache key "matchId:turn" — the platform schema requires a
//   UUID, and the value must be stable across retries of the same turn.
//   action.amount must be OMITTED for HOLD/FORTIFY (the schema rejects it
//   even when it is 0). policyProof.proof and policyProof.public_signals
//   must sit INSIDE policyProof, not at the top level.
//   A missing/mismatched required field is treated as HOLD with no proof.
//   Responses are signed with x-agent-games-signature over the raw body.
//   Retries of the same (matchId, turn) return the byte-identical cached
//   response. A reused nonce under a DIFFERENT (matchId, turn) -> 400.
//
// Policy proof — REVERSE-ENGINEERED from the official vfy-policy circuit
// (the guide publishes the envelope/response schemas and the
// publicInputsHash construction, but NOT the circuit's input names or the
// strategy-param semantics; those below were determined by probing the
// downloaded official circuit with snarkjs + circomlibjs Poseidon and
// confirmed by proofs that verify against the exported vk):
//   Circuit inputs (17 values, nPublic 9):
//     public:  commitment, matchId, turnNumber, selfBalance,
//              opponentBalance, action, amount, circuitVersion
//     private: salt, strategyParams[8]
//   Public signals (output-then-public order):
//     [ Poseidon(matchId, turnNumber, circuitVersion),
//       commitment, matchId, turnNumber, selfBalance, opponentBalance,
//       action, amount, circuitVersion ]
//   commitment = Poseidon(strategyParams[0..7], salt)  (circomlib Poseidon)
//   Action enum: HOLD 0, FORTIFY 1, EXTRACT 2.
//   Param semantics (assert lines from the circuit template VfyPolicyProof_154):
//     params[0] = EXTRACT amount, range 1..16 (line 38), effective 1..10
//                 because the EXTRACT amount itself is capped at 10 (line 95);
//                 params[0] >= 1 is enforced at line 90.
//     params[1] = fortify threshold: FORTIFY iff selfBalance < params[1]
//                 (strict; self == threshold does NOT fortify).
//     params[2] = hold threshold: HOLD iff opponentBalance <= params[2]
//                 (inclusive; opp == threshold DOES hold).
//     params[3] = mode: 0 = normal, 1 = always HOLD (range checked, line 98).
//     params[4..7] must be 0 (lines 75-78; reserved).
//   Decision precedence (verified by proof): FORTIFY first, then HOLD-mode,
//   then low-opponent HOLD, else EXTRACT params[0].
//     if selfBalance < params[1]              -> FORTIFY, amount 0
//     elif params[3] == 1                     -> HOLD, amount 0
//     elif opponentBalance <= params[2]       -> HOLD, amount 0
//     else                                     -> EXTRACT, amount params[0]
//   The circuit does NOT range-check turnNumber or circuitVersion, and it
//   does NOT take fortified state as input — so the policy must not depend
//   on selfFortifiedUntilTurn / opponentFortifiedUntilTurn.
//   matchId -> field element: BigInt("0x" + matchId without dashes), the
//   same encoding the guide's publicInputsHash snippet uses. A non-hex
//   matchId falls back to keccak256(utf8(matchId)) mod FIELD_PRIME
//   (UNCONFIRMED against the platform — same caveat as the gatekeeper's
//   task_id mapping; confirm against the first practice turn).
//
// publicInputsHash (guide, OPTIONAL audit field — the platform verifies the
//   actual proof + public_signals): keccak256 of 8 ABI-packed 32-byte
//   big-endian fields, in order:
//     strategyCommitment.hash, matchId (dashes removed, as hex),
//     turn, selfBalance, opponentBalance, action enum (HOLD 0 / FORTIFY 1 /
//     EXTRACT 2), amount (0 for HOLD/FORTIFY), circuitVersion "v1" -> 1.
//
// Strategy commitment registration (dashboard, Andan): the commitment hash
//   is Poseidon(strategyParams, salt). Register it from Dashboard -> My
//   Agents -> Edit agent (Steal the VFY section) BEFORE the Swiss round
//   pairs — the platform freezes it then and rejects any turn response
//   whose circuitVersion does not match. The salt and params MUST stay
//   stable after registration; changing either changes the commitment and
//   every later proof fails. Use commitment.js to print the hash to register.
//   The salt is a server-side secret (env STEAL_STRATEGY_SALT); it must
//   never be committed, logged, or exposed via /health.
//
// Fail closed: any timeout, uncertainty, proof failure, or commitment
//   mismatch returns HOLD with NO policyProof (the guide resolves that as
//   HOLD, -2) instead of an action we cannot prove.
//
// Secrets: the HMAC secret comes ONLY from AGENT_GAMES_HMAC_SECRET.
// The dashboard-issued secret is required before going live; without it,
// inbound verification is disabled and /health says so. No wallet keys,
// no signing, no spending anywhere in this server.
//
// Env vars:
//   PORT (default 8788), HOST (default 127.0.0.1)
//   AGENT_GAMES_HMAC_SECRET — dashboard secret (required for live)
//   AGENT_GAMES_HMAC_FORMAT — 'hex' (default) or 'sha256='
//   STEAL_STRATEGY_PARAMS — comma-separated 8 ints, default "5,50,0,0,0,0,0,0"
//     (extract 5; fortify when self < 50; never hold-on-low-opponent; normal mode)
//   STEAL_STRATEGY_SALT — hex (32 bytes). Default is a TEST-ONLY salt;
//     set a stable value before going live and register its commitment.
//   STEAL_TURN_TIMEOUT_MS — internal proof guard (default 25000; the
//     platform waits ~30 s per push and the turn deadline is 5 minutes).

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');
const { keccak256, keccak256ModP, FIELD_PRIME } = require('./keccak');

const AGENT_NAME = 'A5YFAM';
const PORT = Number(process.env.PORT || 8788);
const HOST = process.env.HOST || '127.0.0.1';
const HMAC_SECRET = (process.env.AGENT_GAMES_HMAC_SECRET || '').trim();
const HMAC_FORMAT = (process.env.AGENT_GAMES_HMAC_FORMAT || 'hex').trim();
const TURN_TIMEOUT_MS = Number(process.env.STEAL_TURN_TIMEOUT_MS || 25000);
const CIRCUIT_VERSION = 'v1';
const CIRCUIT_VERSION_NUM = 1n;

// TEST-ONLY default salt. Set STEAL_STRATEGY_SALT to a stable value before
// going live, and register the resulting commitment in the dashboard.
const TEST_SALT_HEX =
  '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const SALT_HEX = (process.env.STEAL_STRATEGY_SALT || TEST_SALT_HEX).replace(/^0x/, '');
const SALT = BigInt('0x' + SALT_HEX);

const DEFAULT_PARAMS = [5n, 50n, 0n, 0n, 0n, 0n, 0n, 0n];
function parseParams() {
  const raw = (process.env.STEAL_STRATEGY_PARAMS || '').trim();
  if (!raw) return [...DEFAULT_PARAMS];
  const parts = raw.split(',').map((s) => s.trim());
  if (parts.length !== 8) {
    throw new Error('STEAL_STRATEGY_PARAMS must have exactly 8 comma-separated ints');
  }
  return parts.map((s) => BigInt(s));
}
const STRATEGY_PARAMS = parseParams();

const WASM_PATH = path.join(__dirname, '..', 'circuits', 'vfy-policy.wasm');
const ZKEY_PATH = path.join(__dirname, '..', 'circuits', 'vfy-policy_final.zkey');
const VK_PATH = path.join(__dirname, '..', 'circuits', 'vfy-policy_vk.json');

const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

let poseidon = null; // set at startup
let COMMITMENT = null; // decimal string, Poseidon(strategyParams, salt)
let stealSelfTest = 'pending';

// ---- Poseidon helpers ----
function poseidonHash(values) {
  return poseidon.F.toString(poseidon(values.map((v) => BigInt(v))));
}

function computeCommitment(params, salt) {
  return poseidonHash([...params, salt]);
}

// ---- matchId -> field element ----
function matchIdToField(matchId) {
  const id = String(matchId || '');
  const hex = id.replace(/-/g, '');
  if (/^[0-9a-fA-F]{1,32}$/.test(hex)) {
    return BigInt('0x' + hex);
  }
  // Fallback (UNCONFIRMED against the platform): keccak256 mod p.
  return keccak256ModP([Buffer.from(id, 'utf8')]);
}

// ---- policy (reverse-engineered; see header) ----
function decide(state, params) {
  const self = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  if (self < params[1]) return { type: 'FORTIFY' };
  if (params[3] === 1n) return { type: 'HOLD' };
  if (opp <= params[2]) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: Number(params[0]) };
}

// ---- publicInputsHash (guide's keccak256 construction) ----
function to32be(value) {
  const buf = Buffer.alloc(32);
  const hex = BigInt(value).toString(16).padStart(64, '0');
  buf.write(hex, 0, 'hex');
  return buf;
}

function publicInputsHash(commitment, matchId, turn, selfBalance, opponentBalance, actionType, amount) {
  const matchHex = String(matchId).replace(/-/g, '');
  const fields = [
    to32be(BigInt(commitment)),
    to32be(BigInt('0x' + matchHex)),
    to32be(BigInt(turn)),
    to32be(BigInt(selfBalance)),
    to32be(BigInt(opponentBalance)),
    to32be(ACTION_CODE[actionType]),
    to32be(BigInt(amount)),
    to32be(1n), // circuitVersion "v1" -> 1
  ];
  return '0x' + keccak256(Buffer.concat(fields)).toString('hex');
}

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

// ---- proving ----
function buildCircuitInput(envelope, decision) {
  const state = envelope.state;
  const amount = decision.type === 'EXTRACT' ? BigInt(decision.amount) : 0n;
  return {
    commitment: COMMITMENT,
    matchId: matchIdToField(envelope.matchId).toString(),
    turnNumber: String(envelope.turn),
    selfBalance: String(state.selfBalance),
    opponentBalance: String(state.opponentBalance),
    action: ACTION_CODE[decision.type].toString(),
    amount: amount.toString(),
    circuitVersion: CIRCUIT_VERSION_NUM.toString(),
    salt: SALT.toString(),
    strategyParams: STRATEGY_PARAMS.map((v) => v.toString()),
  };
}

async function proveTurn(envelope, decision) {
  const input = buildCircuitInput(envelope, decision);
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

// ---- turn handling ----
const responseCache = new Map(); // "matchId:turn" -> { status, body }
const seenNonces = new Map(); // nonce -> "matchId:turn"

// ---- deterministic UUIDv5 (RFC 4122) for idempotencyKey ----
// The platform schema requires idempotencyKey to be a UUID. Derive it
// deterministically from the internal cache key "matchId:turn" (SHA-1 over
// the nil-UUID namespace + the name, version/variant bits set), so the
// value is a valid UUID, unique per (matchId, turn), and stable across
// retries of the same turn (the responseCache already returns the
// byte-identical body on replay). Node stdlib crypto only.
const UUID_NAMESPACE_NIL = Buffer.alloc(16); // 00000000-0000-0000-0000-000000000000
function uuidV5(name) {
  const hash = crypto.createHash('sha1')
    .update(UUID_NAMESPACE_NIL)
    .update(Buffer.from(String(name), 'utf8'))
    .digest();
  const b = Buffer.from(hash.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x50; // version 5
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
  const hex = b.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function idempotencyKeyFor(matchId, turn) {
  return uuidV5(`${matchId}:${turn}`);
}

function holdResponse(matchId, turn, reason) {
  // Fail closed: HOLD with NO policyProof (guide: resolved as HOLD, -2).
  return {
    status: 200,
    body: {
      matchId,
      turn,
      action: { type: 'HOLD' },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: idempotencyKeyFor(matchId, turn),
      reason,
    },
  };
}

function isNonNegInt(v) {
  if (typeof v === 'number') return Number.isInteger(v) && v >= 0;
  if (typeof v === 'string') return /^\d+$/.test(v);
  return false;
}

// ---- lazy init (also used when this module is required by the unified
// gatekeeper process, where main() never runs) ----
let readyPromise = null;
async function ensureReady() {
  if (!readyPromise) {
    readyPromise = (async () => {
      poseidon = await buildPoseidon();
      COMMITMENT = computeCommitment(STRATEGY_PARAMS, SALT);
      await selfTest();
    })();
  }
  return readyPromise;
}

function getStealStatus() {
  return {
    commitment: COMMITMENT === null
      ? null
      : '0x' + BigInt(COMMITMENT).toString(16).padStart(64, '0'),
    selfTest: stealSelfTest,
  };
}

// Normalise a commitment value to 64 lowercase hex chars (no 0x prefix),
// or '' when it is not a commitment. Accepts:
//   - a bare string holding a hex value with an optional 0x prefix
//     (any case), 1–64 chars, left-padded with zeros to 64 — a field
//     element rendered by BigInt.toString(16) drops leading zero nibbles
//     (our commitment starts "0e", so it arrives as 63 chars "edb7d80…");
//     a value longer than 64 chars is accepted only when it is extra
//     leading zeros (stripped, then padded to 64);
//   - an object holding that string under any of the keys hash,
//     commitment, value, digest;
//   - a decimal-digit string (the field element as a plain integer) —
//     only when it has at least 20 digits, so ordinary small numbers
//     (balances, turns) are never mistaken for one. The hex form wins
//     when a value is ambiguous (a 64-char digit-only string is read as
//     hex, not decimal); a digit-only string shorter than 64 chars stays
//     on the decimal path unless it contains a hex letter a–f.
function normaliseCommitment(value) {
  let s = '';
  if (typeof value === 'string') {
    s = value.trim();
  } else if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const k of ['hash', 'commitment', 'value', 'digest']) {
      if (typeof value[k] === 'string') { s = value[k].trim(); break; }
    }
    if (!s) return '';
  } else {
    return '';
  }
  const raw = s.toLowerCase().replace(/^0x/, '');
  if (/^[0-9a-f]+$/.test(raw)) {
    let hex = raw;
    if (hex.length > 64) {
      // Longer than 64 nibbles: either extra leading zeros (strip them
      // and continue) or — when the string is all digits — a decimal
      // field element (up to ~77 digits for a 254-bit value), which
      // takes the decimal path below. A longer string containing a–f
      // is neither: reject it.
      const stripped = hex.replace(/^0+/, '');
      if (stripped.length <= 64) {
        hex = stripped;
      } else if (/^\d+$/.test(raw)) {
        try {
          const h = BigInt(raw).toString(16).padStart(64, '0');
          if (/^[0-9a-f]{64}$/.test(h)) return h;
        } catch { /* not a number */ }
        return '';
      } else {
        return '';
      }
    }
    if (hex.length === 0) return '';
    if (hex.length === 64) return hex;
    if (/[a-f]/.test(hex)) return hex.padStart(64, '0');
    // All digits, shorter than 64 chars: a decimal field element
    // (existing precedence), unless too short to be one.
    if (hex.length < 20) return '';
    try {
      const h = BigInt(hex).toString(16).padStart(64, '0');
      if (/^[0-9a-f]{64}$/.test(h)) return h;
    } catch { /* not a number */ }
    return '';
  }
  // Not hex at all: a bare decimal-digit string (no 0x prefix).
  if (/^\d{20,}$/.test(s)) {
    try {
      const h = BigInt(s).toString(16).padStart(64, '0');
      if (/^[0-9a-f]{64}$/.test(h)) return h;
    } catch { /* not a number */ }
  }
  return '';
}

// Extract the envelope's frozen commitment from the known locations
// (fast paths): strategyCommitment:{hash} (guide), strategyCommitment
// as a bare string, envelope.commitment (string or {hash}), or
// envelope.strategyCommitmentHash (string). First non-empty normalised
// value wins. The recursive scan below is the fallback for shapes not
// listed here.
function envelopeCommitment(envelope) {
  return normaliseCommitment(envelope.strategyCommitment)
    || normaliseCommitment(envelope.commitment)
    || normaliseCommitment(envelope.strategyCommitmentHash);
}

// Recursively walk the whole envelope and look for our commitment, so
// the frozen commitment is found wherever the platform nests it (top
// level, input, state, match, ...). Returns { matched, firstCandidate }:
// matched is true when any string (or commitment-shaped object) anywhere
// in the envelope normalises to ourHex; firstCandidate is the first
// normalised value found anywhere (for the mismatch warning). Only
// values that normalise to a 64-hex commitment count as candidates —
// balances, turns, nonces, timestamps and matchIds never do (see
// normaliseCommitment). Depth-capped; cycles guarded (defensive —
// parsed JSON has none).
function scanEnvelopeCommitment(node, ourHex) {
  const out = { matched: false, firstCandidate: '' };
  const seen = new Set();
  const visit = (v, depth) => {
    if (out.matched || v === null || v === undefined || depth > 20) return;
    if (typeof v === 'string' || (typeof v === 'object' && !Array.isArray(v))) {
      const c = normaliseCommitment(v);
      if (c) {
        if (!out.firstCandidate) out.firstCandidate = c;
        if (c === ourHex) { out.matched = true; return; }
      }
    }
    if (typeof v === 'object') {
      if (seen.has(v)) return;
      seen.add(v);
      const children = Array.isArray(v) ? v : Object.values(v);
      for (const child of children) visit(child, depth + 1);
    }
  };
  visit(node, 0);
  return out;
}

// Deep-copy a JSON value with every string truncated to its first 40
// characters, for the mismatch diagnostic log: the envelope shape stays
// visible without printing long values in full. Depth-capped.
function truncateStrings(value, depth = 0) {
  if (typeof value === 'string') {
    return value.length > 40 ? value.slice(0, 40) + '…' : value;
  }
  if (Array.isArray(value)) {
    if (depth > 20) return ['…'];
    return value.map((v) => truncateStrings(v, depth + 1));
  }
  if (value && typeof value === 'object') {
    if (depth > 20) return { '…': '…' };
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = truncateStrings(v, depth + 1);
    return out;
  }
  return value;
}

async function handleSteal(envelope) {
  // When required as a module (unified process), main() never runs, so
  // initialise poseidon / COMMITMENT / self-test lazily on first use.
  await ensureReady();
  const matchId = String(envelope.matchId || '');
  const turn = envelope.turn;
  const cacheKey = `${matchId}:${turn}`;
  if (responseCache.has(cacheKey)) {
    return { cached: responseCache.get(cacheKey) };
  }

  // Validate the envelope shape (fail closed, no proof).
  if (!matchId || !Number.isInteger(turn) || turn < 0 || turn > 20 || !envelope.state) {
    return { status: 400, body: { error: 'invalid_envelope' } };
  }
  const state = envelope.state;
  if (!isNonNegInt(state.selfBalance) || !isNonNegInt(state.opponentBalance)) {
    return { status: 400, body: { error: 'invalid_envelope' } };
  }
  if (BigInt(state.selfBalance) > 100000n || BigInt(state.opponentBalance) > 100000n) {
    return { status: 400, body: { error: 'invalid_envelope' } };
  }

  // Nonce replay: same nonce under a different (matchId, turn) is rejected.
  const nonce = envelope.nonce ? String(envelope.nonce) : '';
  if (nonce) {
    const prev = seenNonces.get(nonce);
    if (prev !== undefined && prev !== cacheKey) {
      return { status: 400, body: { error: 'invalid_nonce_reuse' } };
    }
    if (prev === undefined) seenNonces.set(nonce, cacheKey);
  }

  // The envelope's frozen commitment must match ours, or no valid proof
  // can be produced (circuit line 72). Fast paths first, then a
  // shape-agnostic recursive scan of the whole envelope (the live
  // platform envelope's commitment was not found at any fixed path in
  // the 18:42 and 19:05 practice runs). Fail closed to HOLD, no proof.
  const ourHash = '0x' + BigInt(COMMITMENT).toString(16).padStart(64, '0');
  const ourHex = ourHash.slice(2).toLowerCase();
  const envHex = envelopeCommitment(envelope);
  let matched = !!(envHex && envHex === ourHex);
  let scan = null;
  if (!matched) {
    scan = scanEnvelopeCommitment(envelope, ourHex);
    matched = scan.matched;
  }
  if (!matched) {
    const shown = envHex || (scan && scan.firstCandidate);
    // Distinguish "absent" from "different" for the next live log
    // capture: when no candidate was found anywhere in the envelope,
    // say so explicitly (the [warn] below would only print "(missing)").
    if (!shown) {
      console.warn('[diag] steal envelope: NO commitment candidate found in envelope');
    }
    console.warn('[warn] strategyCommitment mismatch (envelope %s, ours %s) — HOLD, no proof', shown ? shown.slice(0, 18) + '…' : '(missing)', ourHash);
    // Diagnostic: the envelope shape, so a future mismatch can be
    // diagnosed from live logs (blitz.cloud keeps no log history, and a
    // failed practice shows no sanitised request). Strings are truncated
    // to 40 chars; the envelope is the platform's task payload and
    // contains no secrets (the HMAC signature is a header, not the body).
    console.warn('[diag] steal envelope keys=[%s] body=%s',
      Object.keys(envelope).join(','),
      JSON.stringify(truncateStrings(envelope)));
    const r = holdResponse(matchId, turn, 'COMMITMENT_MISMATCH');
    responseCache.set(cacheKey, { status: r.status, body: JSON.stringify(r.body) });
    return r;
  }

  // Deadline guard: the platform waits ~30 s per push; turn deadline is 5 min.
  let timeoutMs = TURN_TIMEOUT_MS;
  if (envelope.deadlineAt) {
    const msLeft = Date.parse(envelope.deadlineAt) - Date.now();
    if (Number.isFinite(msLeft)) {
      if (msLeft <= 0) {
        const r = holdResponse(matchId, turn, 'DEADLINE_PASSED');
        responseCache.set(cacheKey, { status: r.status, body: JSON.stringify(r.body) });
        return r;
      }
      timeoutMs = Math.max(2000, Math.min(TURN_TIMEOUT_MS, msLeft - 500));
    }
  }

  const decision = decide(state, STRATEGY_PARAMS);
  const amount = decision.type === 'EXTRACT' ? decision.amount : 0;
  try {
    const { proof, publicSignals } = await withTimeout(proveTurn(envelope, decision), timeoutMs);
    const action = decision.type === 'EXTRACT'
      ? { type: 'EXTRACT', amount }
      : { type: decision.type };
    const body = {
      matchId,
      turn,
      action,
      policyProof: {
        circuitVersion: CIRCUIT_VERSION,
        proof,
        public_signals: publicSignals,
        publicInputsHash: publicInputsHash(
          COMMITMENT, matchId, turn, state.selfBalance, state.opponentBalance,
          decision.type, amount,
        ),
      },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: idempotencyKeyFor(matchId, turn),
    };
    responseCache.set(cacheKey, { status: 200, body: JSON.stringify(body) });
    return { status: 200, body };
  } catch (e) {
    console.error('[steal] proof failed:', e.message);
    const r = holdResponse(matchId, turn, 'PROOF_FAILED');
    responseCache.set(cacheKey, { status: r.status, body: JSON.stringify(r.body) });
    return r;
  }
}

// ---- startup self-test ----
async function selfTest() {
  try {
    const envelope = {
      matchId: '9f4e1b2a-0000-0000-0000-000000000000',
      turn: 3,
      state: { selfBalance: '95', opponentBalance: '105' },
      strategyCommitment: { hash: '0x' + BigInt(COMMITMENT).toString(16).padStart(64, '0') },
    };
    const decision = decide(envelope.state, STRATEGY_PARAMS);
    const { proof, publicSignals } = await proveTurn(envelope, decision);
    const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const expectedOut = poseidonHash([
      matchIdToField(envelope.matchId), BigInt(envelope.turn), CIRCUIT_VERSION_NUM,
    ]);
    const outOk = publicSignals[0] === expectedOut;
    stealSelfTest = ok && outOk
      ? `PASS (${decision.type} proof verifies locally, output matches Poseidon(matchId, turn, 1))`
      : `FAIL (verify=${ok}, outputMatch=${outOk})`;
  } catch (e) {
    stealSelfTest = 'FAIL: ' + e.message;
  }
}

// ---- HTTP server ----
const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, {
        ok: true,
        agent: AGENT_NAME,
        track: 'steal-the-vfy',
        hmacConfigured: !!HMAC_SECRET,
        commitment: '0x' + BigInt(COMMITMENT).toString(16).padStart(64, '0'),
        circuitVersion: CIRCUIT_VERSION,
        selfTest: stealSelfTest,
        uptimeSec: Math.floor(process.uptime()),
      });
    }

    if (req.method === 'GET' && req.url === '/') {
      return sendJson(res, 200, {
        service: 'agent-games',
        agent: AGENT_NAME,
        tracks: ['steal-the-vfy'],
        endpoints: ['POST /steal', 'POST /agent', 'GET /health'],
      });
    }

    if (req.method !== 'POST' || (req.url !== '/steal' && req.url !== '/agent')) {
      return sendJson(res, 404, { error: 'not found' });
    }

    const rawBody = await readBody(req);

    if (HMAC_SECRET) {
      const sig = req.headers['x-agent-games-signature'];
      if (!verifySignature(HMAC_SECRET, rawBody, sig, HMAC_FORMAT)) {
        console.warn('[warn] HMAC mismatch on %s', req.url);
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

    if (obj && obj.eventId && obj.eventId !== 'steal-the-vfy') {
      return sendJson(res, 400, { error: 'invalid_event' });
    }

    const result = await handleSteal(obj);
    if (result.cached) return sendCached(res, result.cached);
    return sendJson(res, result.status, result.body, true);
  } catch (e) {
    console.error('[server] unhandled error:', e);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

async function main() {
  await ensureReady();
  console.log(`[server] ${AGENT_NAME} steal-the-vfy starting (port ${PORT})`);
  console.log(`[server] HMAC secret: ${HMAC_SECRET ? 'configured' : 'NOT SET (inbound verification disabled)'}`);
  console.log(`[server] strategy params: [${STRATEGY_PARAMS.join(', ')}]`);
  console.log(`[server] commitment: 0x${BigInt(COMMITMENT).toString(16).padStart(64, '0')}`);
  if (SALT_HEX === TEST_SALT_HEX) {
    console.log('[server] WARNING: using the TEST-ONLY salt. Set STEAL_STRATEGY_SALT before going live.');
  }
  server.listen(PORT, HOST, () => {
    console.log(`[server] listening on ${HOST}:${PORT}`);
    console.log(`[server] self-test steal: ${stealSelfTest}`);
  });
}

if (require.main === module) {
  main().catch((e) => {
    console.error('[server] startup failed:', e);
    process.exit(1);
  });
}

module.exports = {
  server,
  decide,
  computeCommitment,
  matchIdToField,
  publicInputsHash,
  ACTION_CODE,
  handleSteal,
  ensureReady,
  getStealStatus,
  normaliseCommitment,
  envelopeCommitment,
  scanEnvelopeCommitment,
  truncateStrings,
};
