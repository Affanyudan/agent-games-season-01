# Agent Games Season 01 — A5YFAM (Proof Gatekeeper, local build)

Status: **LOCAL BUILD + TEST ONLY — 16/16 checks passed.** No registration, no
form submission, no GitHub repo created, no deployment, no spending, no
credentials used. Built 2026-11-16 ~01:00 WIB.

Agent name: **A5YFAM**. Tracks chosen: **both, Gatekeeper first**.
Registration closes 21 Nov 2026 22:00 UTC. Gatekeeper round 4 opens 16 Nov 17:30 WIB.

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
│   └── gatekeeper_vk.json     verification key exported from the zkey
└── gatekeeper/
    ├── server.js              the gatekeeper (single file, stdlib http + snarkjs)
    ├── keccak.js              pure-JS Keccak-256 (Node has only NIST SHA3)
    ├── test.js                local test harness (16 checks)
    ├── package.json / package-lock.json   (snarkjs 0.7.6, local node_modules only)
    └── node_modules/          snarkjs 0.7.6
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

Exported verification key: Groth16, curve bn128, **nPublic 13** — matches the
documented 13 public signals.

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
7. **Steal the VFY (second track).** Not built yet. Needs the vfy-policy
   circuit files, a strategy commitment (Poseidon of 8 params + salt)
   registered before the Swiss round pairs, and the `/steal` endpoint. The
   form says Steal stays open through the tournament and a new agent joins
   from the next Swiss round.
8. **Kurier (optional).** On-chain proof finalization via Kurier is optional
   — the server always responds with the local proof. A Kurier API key is not
   configured; adding it is best-effort only.

## Deploy (prepared, not deployed)

- `Dockerfile` (root of this dir) builds a host-agnostic image: Node 20-slim,
  `npm ci` in `gatekeeper/`, circuits copied to `/app/circuits`, `HOST=0.0.0.0`,
  `PORT=8787`, `CMD node gatekeeper/server.js`. Works on Railway, Fly.io,
  Render, or any Docker host. Build it on the deploy host before relying on it.
- `gatekeeper/.env.example` lists the env vars; set `AGENT_GAMES_HMAC_SECRET`
  (dashboard-issued, after registration) as a host secret — never commit it.
- `package.json` has `"start": "node server.js"`, so Railway/Nixpacks also works
  without Docker.
- Still needed to actually deploy: the public repo (push needs Andan's GitHub
  login) and a hosting account.
