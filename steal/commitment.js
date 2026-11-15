// Print the strategy commitment hash to register in the dashboard.
// Usage:
//   STEAL_STRATEGY_PARAMS="5,50,0,0,0,0,0,0" STEAL_STRATEGY_SALT=<hex> node commitment.js
// The commitment is Poseidon(strategyParams[0..7], salt) on BN254.
// Register the printed hash from Dashboard -> My Agents -> Edit agent
// (Steal the VFY section) BEFORE the Swiss round pairs. The salt and
// params must then stay unchanged — changing either changes the commitment
// and every later proof fails (circuit line 72).
// NEVER print the salt's security value anywhere public; the commitment
// hash itself is public (it is sent in every turn envelope).

const { buildPoseidon } = require('circomlibjs');

const DEFAULT_PARAMS = [5n, 50n, 0n, 0n, 0n, 0n, 0n, 0n];
const TEST_SALT_HEX =
  '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

function parseParams() {
  const raw = (process.env.STEAL_STRATEGY_PARAMS || '').trim();
  if (!raw) return [...DEFAULT_PARAMS];
  const parts = raw.split(',').map((s) => s.trim());
  if (parts.length !== 8) throw new Error('STEAL_STRATEGY_PARAMS must have exactly 8 ints');
  return parts.map((s) => BigInt(s));
}

(async () => {
  const params = parseParams();
  const saltHex = (process.env.STEAL_STRATEGY_SALT || TEST_SALT_HEX).replace(/^0x/, '');
  const salt = BigInt('0x' + saltHex);
  const poseidon = await buildPoseidon();
  const commitment = poseidon.F.toString(poseidon([...params, salt]));
  console.log('strategy params: [' + params.join(', ') + ']');
  console.log('salt (first 12 hex chars): ' + saltHex.slice(0, 12) + '...' + (saltHex === TEST_SALT_HEX ? ' (TEST-ONLY salt — set STEAL_STRATEGY_SALT before going live)' : ''));
  console.log('commitment to register in the dashboard:');
  console.log('0x' + BigInt(commitment).toString(16).padStart(64, '0'));
  process.exit(0);
})().catch((e) => {
  console.error('error:', e.message);
  process.exit(1);
});
