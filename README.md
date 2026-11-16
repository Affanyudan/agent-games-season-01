# Agent Games Season 01 — A5YFAM (Proof Gatekeeper + Steal the VFY, local build)

Status: **LOCAL BUILD + TEST ONLY — Gatekeeper 16/16 checks passed, Steal
19/19 checks passed.** No registration, no form submission, no deployment,
no spending, no credentials used. Gatekeeper built 2026-11-16 ~01:00 WIB;
Steal built 2026-11-16 ~01:30 WIB.

Agent name: **A5YFAM**. Tracks chosen: **both, Gatekeeper first**.
Registration closes 21 Nov 2026 22:00 UTC. Gatekeeper round 4 opens 16 Nov 17:30 WIB.
Steal the VFY Swiss stage runs 13–17 Nov 2026 (see open item 9).

## What this is

A Proof Gatekeeper server for zkVerify Agent Games Season 01. The platform
POSTs a signed JSON task envelope to the agent's public HTTPS endpoint; the
agent verifies the HMAC, decides APPROVE/REJECT against the seven trap
varieties, and returns the decision with a Groth16 proof (BN254, Circom 2.x)
from the tournament's own circuit. Scoring: correct verified decision +12,
wrong REJECT −3, wrong APPROVE −6, timeout/missing proof −2.

## Files

```
agent-games/
├── README.md                  this file
├── circuits/
│   ├── gatekeeper.wasm        official circuit (1,755,820 bytes)
│   ├── gatekeeper_final.zkey  official proving key (309,750 bytes)
│   ├── gatekeeper_vk.json     verification key exported from the zkey
│   ├── vfy-policy.wasm        official circuit (2,991,212 bytes)
│   ├── vfy-policy_final.zkey  official proving key
│   └── vfy-policy_vk.json     verification key exported from the zkey
├── gatekeeper/
│   ├── server.js              the gatekeeper (single file, stdlib http + snarkjs)
│   ├── keccak.js              pure-JS Keccak-256 (Node has only NIST SHA3)
│   ├── test.js                local test harness (16 checks)
│   ├── package.json / package-lock.json   (snarkjs 0.7.6, local node_modules only)
│   └── node_modules/          snarkjs 0.7.6
└── steal/
    ├── server.js              the steal agent (single file, stdlib http + snarkjs + circomlibjs)
    ├── keccak.js              copy of the Keccak-256 helper
    ├── commitment.js          prints the commitment hash to register in the dashboard
    ├── test.js                local test harness (19 checks)
    ├── .env.example           env vars (HMAC secret, strategy params, salt)
    ├── package.json / package-lock.json   (snarkjs 0.7.6, circomlibjs, local node_modules only)
    └── node_modules/          snarkjs 0.7.6 + circomlibjs
```

## Sources (official)

- Builder Field Guide: https://agentgames.zkverify.io/build
- Getting started / FAQ: https://agentgames.zkverify.io/guide
- Circuit info JSON: https://agentgames.zkverify.io/api/circuit-info
  - gatekeeper vkHash: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  - wasm: https://agentgames.zkverify.io/circuits/gatekeeper.wasm
  - zkey: https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
  - vfy-policy (Steal the VFY) vkHash:
    `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
    (not downloaded yet — Steal is second priority)

Circuit file hashes (sha256, downloaded 2026-11-16):

| file | sha256 |
|---|---|
| gatekeeper.wasm | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| gatekeeper_final.zkey | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| vfy-policy.wasm | `bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2` |
| vfy-policy_final.zkey | `f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41` |

Exported verification keys: Gatekeeper Groth16, curve bn128, **nPublic 13** —
matches the documented 13 public signals. Vfy-policy Groth16, curve bn128,
**nPublic 9** — 1 output + 8 public inputs (see the Steal section).

## Protocol (as implemented)

- `POST /gatekeeper` — HMAC-SHA256 in header `x-agent-games-signature` over
  the RAW body, verified BEFORE parsing (bad signature → 401, no work done).
  Formats: `hex` (default) or `sha256=` (env `AGENT_GAMES_HMAC_FORMAT`).
- Preflight `{"type":"agent-games.preflight.v1"}` →
  `{ok:true, protocolVersion:"v1"}`, signed.
- Task fields (inside `input` or top-level): `registered_vk`, `proof_vk`,
  `minimum`, `public_balance`, `expiry_block`, `current_block`, `recipient`,
  `condition_recipient`, `amount`, `max_transfer`, plus `proof_tx`, `task_id`.
- Decision order (first failing check wins; fail closed):
  `VK_SUBSTITUTION` → `PROOF_REUSED` (same `proof_tx` under a DIFFERENT
  `task_id`; a retry of the SAME `task_id` is not reuse) → `THRESHOLD_MISMATCH`
  (`public_balance < minimum`; `==` minimum is VALID) → `EXPIRED_CONDITION`
  (`current_block >= expiry_block`; expiry is STRICT) → `RECIPIENT_MISMATCH`
  (case-insensitive) → `AMOUNT_OVERFLOW` (`amount > max_transfer`; `==` max
  is VALID) → `VALID_CONDITION` → APPROVE.
- Proof: `snarkjs.groth16.fullProve` with the official wasm/zkey.
  Circuit inputs: `registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, decision (1=APPROVE, 0=REJECT), taskId, salt (private, random)`.
  Response: `{decision, reason_code, proof_tx, proof, public_signals}`.
  `PROOF_REUSED` returns no proof fields. If proving an APPROVE fails, the
  server fails closed to REJECT (`PROOF_FAILED`) instead of returning an
  approval it cannot prove.
- Every response is signed with `x-agent-games-signature` over the raw body.
- Retries of the same `task_id` return the byte-identical cached response.
- `GET /health` → `{ok, agent, track, hmacConfigured, taskIdMode, selfTest,
  uptimeSec}`. `GET /` → service info.
- 60 s hard deadline: local proof takes ~0.4 s; a 45 s internal guard fails
  closed to REJECT if proving ever stalls.

## How to run (local)

```sh
cd ~/workspace/tools/agent-games/gatekeeper
# test secret ONLY — never a real dashboard secret:
AGENT_GAMES_HMAC_SECRET=test-secret-local-only-do-not-use-live PORT=8787 node server.js
# in another shell:
node test.js
```

Env vars: `PORT` (default 8787), `HOST` (default 127.0.0.1),
`AGENT_GAMES_HMAC_SECRET` (dashboard secret; without it inbound HMAC is
disabled and /health says so), `AGENT_GAMES_HMAC_FORMAT` (`hex`|`sha256=`),
`GATEKEEPER_TASK_ID_MODE` (`keccak`|`numeric`|`hex`, see open item 1).

## Test results — 16/16 PASSED (2026-11-16 ~01:00 WIB)

Run: `node test.js` (spawns the server on 127.0.0.1:8789 with the local test
secret; no external network).

| # | check | result |
|---|---|---|
| 01 | valid task → APPROVE, proof verifies vs exported vk | PASS — status 200, decision APPROVE, verify=true, round trip 321 ms, 13 signals, decision signal=1 |
| 02 | VK substitution → REJECT VK_SUBSTITUTION | PASS |
| 03 | proof reuse (same proof_tx, different task_id) → REJECT PROOF_REUSED, no proof | PASS — proofPresent=false |
| 04 | threshold mismatch → REJECT THRESHOLD_MISMATCH | PASS |
| 05 | expired condition → REJECT EXPIRED_CONDITION | PASS |
| 06 | recipient mismatch → REJECT RECIPIENT_MISMATCH | PASS |
| 07 | amount overflow → REJECT AMOUNT_OVERFLOW | PASS |
| 08 | bad HMAC → 401 bad_signature | PASS |
| 09 | replay same task_id → byte-identical response | PASS — identical=true |
| 10 | malformed task (missing field) → REJECT INVALID_TASK | PASS |
| 11 | boundary balance == minimum → APPROVE | PASS |
| 12 | boundary amount == max_transfer → APPROVE | PASS |
| 13 | boundary current_block == expiry_block → REJECT EXPIRED_CONDITION | PASS |
| 14 | circuit refuses APPROVE on trap inputs (direct fullProve, decision=1) | PASS — threw `Assert Failed. Error in template GatekeeperEvaluation_79 line: 102` in 94 ms |
| 15 | preflight → {ok:true, protocolVersion:v1} + signed response | PASS |
| 16 | GET /health → ok:true, hmacConfigured:true | PASS |

Proof-generation time: **direct fullProve 421 ms** on the valid input (verifies=true,
13 signals); valid-task round trip through the server 321 ms. Both far inside
the 60,000 ms deadline. Startup self-test: PASS (APPROVE proof verifies locally).
Keccak-256 self-test: both known vectors PASS (empty string and "abc").

## Steal the VFY — local build (19/19 checks passed, 2026-11-16 ~01:30 WIB)

Two agents play a 20-turn match from 100 VFY each. Every move carries a
Groth16 policy proof; a missing/invalid proof is −2 and the turn resolves
as HOLD. Scoring: win +18, draw +9, loss +3, reliability bonus +0 to +2,
timeout −1/turn. Turn deadline 5 minutes (the platform waits ~30 s per
push). Swiss stage 13–17 Nov, 7 rounds → Top 16 knockout.

### Protocol (as implemented in `steal/server.js`)

- `POST /steal` (the guide's example path is `POST /agent`; both accepted)
  — HMAC-SHA256 in header `x-agent-games-signature` over the RAW body,
  verified BEFORE parsing (bad signature → 401). Preflight
  `{"type":"agent-games.preflight.v1"}` → `{ok:true, protocolVersion:"v1"}`, signed.
- Turn envelope: `matchId` (UUID), `turn`, `state:{selfBalance,
  opponentBalance, selfFortifiedUntilTurn, opponentFortifiedUntilTurn}`,
  `strategyCommitment:{hash}`, `deadlineAt`, `nonce`. The commitment is
  accepted in several shapes (the platform's live envelope does not
  always use `strategyCommitment:{hash}`): a bare string, `{hash}` with
  or without the `0x` prefix (case-insensitive), `envelope.commitment`
  (string or `{hash}`), or `envelope.strategyCommitmentHash`.
- Response: `{matchId, turn, action:{type, amount?},
  policyProof:{circuitVersion:"v1", proof, public_signals,
  publicInputsHash}, agentTimestamp, idempotencyKey}`. `action.amount` is
  OMITTED for HOLD/FORTIFY (the schema rejects it even as 0). Proof and
  public signals sit INSIDE `policyProof`. `idempotencyKey` is a
  deterministic UUIDv5 (nil-UUID namespace) of the internal cache key
  `"matchId:turn"` — the platform schema requires a UUID. Retries of the
  same `(matchId, turn)` return the byte-identical cached response; a
  reused nonce under a different turn → 400. A genuine commitment
  mismatch still fails closed to HOLD with NO policyProof: the strict
  practice schema rejects that response (policyProof is required), but
  live play resolves it as HOLD, −2, per the guide.
- `publicInputsHash`: keccak256 of 8 ABI-packed 32-byte big-endian fields
  (commitment, matchId dashes removed, turn, selfBalance, opponentBalance,
  action enum HOLD 0 / FORTIFY 1 / EXTRACT 2, amount, circuitVersion 1) —
  exactly the guide's construction; verified against the response in test 05.

### Policy proof — reverse-engineered from the official circuit

The guide publishes the envelope/response schemas and the hash
construction, but NOT the circuit's input names or the strategy-param
semantics. Those were determined by probing the downloaded official
`vfy-policy` circuit (signal sizes via the wasm's `getInputSignalSize`,
then assert-line mapping by varying one input at a time) and confirmed by
proofs that verify against the exported vk:

- Circuit inputs (17 values, nPublic 9): public `commitment, matchId,
  turnNumber, selfBalance, opponentBalance, action, amount,
  circuitVersion`; private `salt, strategyParams[8]`.
- Public signals (output-then-public):
  `[Poseidon(matchId, turnNumber, circuitVersion), commitment, matchId,
  turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion]`.
- `commitment = Poseidon(strategyParams[0..7], salt)` (circomlib Poseidon;
  circuit template line 72). The published vfy-policy vkHash
  `0x6c56509f…74be047` does NOT match keccak256 (`0x31b9e169…a939a232`) or
  sha256 (`0x69408039…e9bce38c03`) over the compact exported vk JSON — same
  situation as the gatekeeper (see open item 2); local proofs verify
  against the exported vk.
- Param semantics (template `VfyPolicyProof_154` assert lines):
  `params[0]` = EXTRACT amount, range 1..16 (line 38), effective 1..10
  because the amount itself is capped at 10 (line 95); `params[0] >= 1`
  enforced at line 90. `params[1]` = fortify threshold: FORTIFY iff
  `selfBalance < params[1]` (strict). `params[2]` = hold threshold: HOLD
  iff `opponentBalance <= params[2]` (inclusive). `params[3]` = mode:
  0 normal, 1 always HOLD (range-checked, line 98). `params[4..7]` must
  be 0 (lines 75–78, reserved).
- Decision precedence (verified by proof): FORTIFY first, then HOLD-mode,
  then low-opponent HOLD, else EXTRACT `params[0]`.
- The circuit does NOT range-check `turnNumber` or `circuitVersion`, and
  takes NO fortified state as input — so the policy must not depend on
  `selfFortifiedUntilTurn` / `opponentFortifiedUntilTurn`.
- `matchId` → field element: `BigInt("0x" + matchId without dashes)`, the
  encoding the guide's hash snippet uses; a non-hex matchId falls back to
  keccak256 mod FIELD_PRIME (UNCONFIRMED against the platform — confirm
  against the first practice turn).
- Default strategy (env `STEAL_STRATEGY_PARAMS`, default
  `5,50,0,0,0,0,0,0`): extract 5; fortify when self < 50; never
  hold-on-low-opponent; normal mode. A starter, not a tuned strategy.
  The salt (`STEAL_STRATEGY_SALT`, test-only default in the code) and the
  params MUST stay frozen after the commitment is registered — changing
  either breaks every later proof. `steal/commitment.js` prints the hash
  to register in the dashboard (Dashboard → My Agents → Edit agent,
  Steal the VFY section) BEFORE the Swiss round pairs.
- Fail closed: commitment mismatch, proof failure, timeout, or passed
  deadline → HOLD with NO `policyProof` (guide: resolved as HOLD, −2).

### How to run (local)

```sh
cd ~/workspace/tools/agent-games/steal
# test secret + test salt ONLY — never live values:
AGENT_GAMES_HMAC_SECRET=test-secret-local-only-do-not-use-live \
STEAL_STRATEGY_PARAMS=5,50,0,0,0,0,0,0 \
STEAL_STRATEGY_SALT=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
PORT=8788 node server.js
# in another shell:
node test.js
# print the commitment hash to register in the dashboard:
node commitment.js
```

### Test results — 19/19 PASSED (2026-11-16 ~01:30 WIB)

Run: `node test.js` (spawns two servers on 127.0.0.1:8790/8791 with the
local test secret/salt; no external network).

| # | check | result |
|---|---|---|
| 01 | both servers healthy, self-test PASS | PASS — commitments `0x0679c2c0…` (default params) and `0x2f872b7f…` (hold-mode params) |
| 02 | /health commitment == Poseidon(params, salt) | PASS |
| 03 | valid EXTRACT turn (95/105) → 200, proof verifies | PASS — EXTRACT 5, round trip 633 ms |
| 04 | public signals are output-then-public, as expected | PASS — 9 signals, output == Poseidon(matchId, turn, 1) |
| 05 | publicInputsHash matches the guide construction | PASS |
| 06 | response is signed | PASS |
| 07 | FORTIFY when self < 50, no amount field, proof verifies | PASS |
| 08 | HOLD when opponent <= 0, no amount field, proof verifies | PASS |
| 09 | HOLD-mode params (p3=1) → HOLD, proof verifies | PASS |
| 10 | FORTIFY beats HOLD-mode when self < 50 | PASS |
| 11 | bad HMAC → 401 | PASS |
| 12 | malformed envelope (missing matchId) → 400 | PASS |
| 13 | replay same turn → byte-identical | PASS — identical=true |
| 14 | commitment mismatch → HOLD, no proof | PASS — reason=COMMITMENT_MISMATCH |
| 15 | nonce reuse across turns → 400 | PASS — first=200 second=400 |
| 16 | preflight → ok:true, protocolVersion:v1, signed | PASS |
| 17 | POST /agent also accepts a turn | PASS |
| 18 | full 20-turn match vs stub opponent (always EXTRACT 5): every turn 200 + proof verifies + action as expected | PASS — final self=100 opp=100 (symmetric 5-for-5 trades), max turn round trip 698 ms |
| 19 | max turn round trip far inside the 5-minute deadline | PASS — max 698 ms vs 300,000 ms deadline, ~30 s platform push wait |

Notes: the simulated match was all-EXTRACT (balances never crossed the
fortify/hold thresholds); the FORTIFY/HOLD branches are covered by checks
07–10 individually. Direct fullProve timings seen during probing: ~90–420 ms
per proof. The public Steal reference build found during research
(Kaneka0510/steal-the-vfy-agent, "Skylar") is a proof STUB (returns null)
and its response format/action names (`STEAL`, top-level proof fields)
contradict the official guide — the guide wins; only its HMAC-first
structure was used as a cross-check.

## Open items / things still needed before it can play

1. **task_id → field mapping is UNCONFIRMED.** The guide does not publish how
   the platform maps the string `task_id` to the circuit's `taskId` field
   element. Default implemented: `keccak256(utf8(task_id)) mod FIELD_PRIME`
   (env `GATEKEEPER_TASK_ID_MODE=keccak`; alternatives `numeric`, `hex`).
   Confirm against the first practice task: if its proof is rejected, switch
   the mode and retry. No other code changes needed.
2. **Registered vk hash not reproduced locally.** The published registered
   vkHash `0x6b79c6…d77b0` does not match keccak256 or sha256 over the compact
   JSON of the exported verification key (same finding as an independent
   public build, which tried 12 serialization variants). zkVerify/Kurier
   presumably hash their own canonical serialization. Local proofs verify
   against the exported vk, so the artifacts are self-consistent — but resolve
   this before trusting a live round, because the platform re-verifies proofs
   against *its* registered key.
3. **Registration (Andan, on his phone, already logged in).** Form fields:
   name `A5YFAM`; tracks Proof Gatekeeper + Steal the VFY; a PUBLIC GitHub
   repo on his personal account (required) — GitHub username Affanyudan
   (https://github.com/Affanyudan). NOTE: a repo named
   `agent-games-season-01` was reported created but its URL returned 404 when
   checked twice — verify the exact public repo URL before submitting the form.
   Endpoint is optional at registration and is filled after deployment.
4. **Public HTTPS hosting.** The server must run at a stable public HTTPS
   endpoint (e.g. Railway from the public repo) that the dashboard can
   register. No tunnel/hosting was set up in this local build.
5. **Real HMAC secret.** After registration, set the dashboard-issued secret
   ("Rotate Secret") as `AGENT_GAMES_HMAC_SECRET` on the host. The dashboard
   preflight fails with "The endpoint must return signed protocol-v1 JSON" if
   responses are unsigned — this build signs every response when the secret is
   set. Never commit the secret; never use the local test secret live.
6. **Dashboard health check + practice tasks.** After deploy, confirm the
   dashboard marks the agent HEALTHY and run unscored practice tasks first;
   verify a practice APPROVE/REJECT against the platform (this also settles
   open items 1–2).
7. **Steal the VFY — BUILT 2026-11-16 ~01:30 WIB (19/19 local checks).**
   Still needed before it can play: register the strategy commitment in
   the dashboard before the Swiss round pairs (see 9–10 below), deploy
   the steal server alongside the gatekeeper (see 11), and run a practice
   turn first (see 12).
8. **Kurier (optional).** On-chain proof finalization via Kurier is optional
   — the server always responds with the local proof. A Kurier API key is not
   configured; adding it is best-effort only.
9. **Steal entry status is CONFLICTED — verify on the dashboard.** The
   registration form and the official /events/steal-the-vfy page say a new
   agent joins from the next Swiss round until the final round is paired,
   but two public participant reports dated 15 Nov 2026 say Steal entries
   had already locked once the Swiss tournament was pairing (Swiss stage
   13–17 Nov). Do not assume entry is possible: check the dashboard
   (My Agents → Edit agent, Steal the VFY section) before spending more
   build effort on Steal.
10. **Strategy commitment registration (Steal).** Register the commitment
    hash from `steal/commitment.js` in the dashboard BEFORE the Swiss
    round pairs. The params and salt must then stay frozen. Default
    params `5,50,0,0,0,0,0,0` are a starter, not a tuned strategy —
    tuning them is Andan's call; any change needs a new commitment
    registered before the next pairing. The live salt must be a stable
    host secret (generate with `openssl rand -hex 32`), never the test salt.
11. **Hosting — UNIFIED endpoint (fixed 2026-11-16).** The dashboard
    registers ONE endpoint per agent and sends BOTH tracks' tasks to it,
    so the Gatekeeper process (`gatekeeper/server.js`, root `Dockerfile`,
    port 8787) also serves Steal turns: it routes envelopes by shape
    (`matchId` / `eventId: 'steal-the-vfy'` / type containing 'steal' ->
    `steal/server.js`'s `handleSteal`; everything else -> Gatekeeper).
    The root `Dockerfile` installs the Steal deps too (circomlibjs) and
    copies `steal/server.js` + `steal/keccak.js`. The standalone Steal
    service (`Dockerfile.steal`, port 8788) still runs independently.
    The Gatekeeper app needs env `STEAL_STRATEGY_SALT` (real salt) and
    `STEAL_STRATEGY_PARAMS=5,50,0,0,0,0,0,0` or its Steal commitment
    will not match the registered one.
12. **Practice turns (both tracks).** After deploy, run unscored practice
    turns first and confirm the platform accepts the proofs. For Steal
    this also settles: (a) the `matchId` → field mapping (raw hex is the
    default; keccak fallback is unconfirmed), and (b) the vfy-policy
    registered vkHash `0x6c56509f…74be047`, which does not match keccak256
    or sha256 over the compact exported vk (same finding as the
    gatekeeper's item 2).

## Deploy (prepared, not deployed)

- `Dockerfile` (root of this dir) builds a host-agnostic image: Node 20-slim,
  `npm ci` in `gatekeeper/`, circuits copied to `/app/circuits`, `HOST=0.0.0.0`,
  `PORT=8787`, `CMD node gatekeeper/server.js`. Works on Railway, Fly.io,
  Render, or any Docker host. Build it on the deploy host before relying on it.
  NOTE: it runs the Gatekeeper only. Steal needs a second process on its own
  port (e.g. a second service running `node steal/server.js` with
  `STEAL_STRATEGY_PARAMS` / `STEAL_STRATEGY_SALT` set, `PORT=8788`) — see
  open item 11.
- `gatekeeper/.env.example` lists the env vars; set `AGENT_GAMES_HMAC_SECRET`
  (dashboard-issued, after registration) as a host secret — never commit it.
- `package.json` has `"start": "node server.js"`, so Railway/Nixpacks also works
  without Docker.
- Still needed to actually deploy: the public repo (push needs Andan's GitHub
  login) and a hosting account.
