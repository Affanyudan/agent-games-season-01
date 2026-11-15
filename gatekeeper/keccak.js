// Minimal pure-JS Keccak-256 (original Keccak padding, NOT NIST SHA3).
// No dependency: Node's crypto has sha3-256 (NIST padding), which is a
// DIFFERENT hash. Used only to map a string task_id to a BN254 field
// element: keccak256(utf8(task_id)) mod FIELD_PRIME.
// Self-test vectors (well-known):
//   keccak256("")    = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
//   keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45

const MASK = (1n << 64n) - 1n;
const FIELD_PRIME =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets r[x][y] from the Keccak spec.
const R = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl(v, n) {
  if (n === 0) return v & MASK;
  const b = BigInt(n);
  return ((v << b) | (v >> (64n - b))) & MASK;
}

function keccakF1600(s) {
  for (let round = 0; round < 24; round++) {
    // Theta
    const c = new Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4];
    }
    const d = new Array(5);
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) s[x][y] ^= d[x];
    }
    // Rho + Pi
    const b = Array.from({ length: 5 }, () => new Array(5).fill(0n));
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y][(2 * x + 3 * y) % 5] = rotl(s[x][y], R[x][y]);
      }
    }
    // Chi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        s[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]);
      }
    }
    // Iota
    s[0][0] ^= RC[round];
  }
}

// Keccak-256: rate 136 bytes, suffix 0x01, pad10*1.
function keccak256(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const state = Array.from({ length: 5 }, () => new Array(5).fill(0n));
  const RATE = 136;
  let offset = 0;
  // Absorb full blocks (little-endian lane assembly).
  while (offset + RATE <= input.length) {
    const block = input.subarray(offset, offset + RATE);
    for (let i = 0; i < RATE; i++) {
      const lane = (i / 8) | 0;
      const bytePos = i % 8;
      state[lane % 5][Math.floor(lane / 5)] ^= BigInt(block[i]) << BigInt(8 * bytePos);
    }
    keccakF1600(state);
    offset += RATE;
  }
  // Final block with pad10*1, suffix 0x01.
  const tail = Buffer.alloc(RATE, 0);
  input.copy(tail, 0, offset);
  tail[input.length - offset] ^= 0x01;
  tail[RATE - 1] ^= 0x80;
  for (let i = 0; i < RATE; i++) {
    const lane = (i / 8) | 0;
    const bytePos = i % 8;
    state[lane % 5][Math.floor(lane / 5)] ^= BigInt(tail[i]) << BigInt(8 * bytePos);
  }
  keccakF1600(state);
  // Squeeze 32 bytes, little-endian.
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    const lane = (i / 8) | 0;
    const bytePos = i % 8;
    out[i] = Number((state[lane % 5][Math.floor(lane / 5)] >> BigInt(8 * bytePos)) & 0xffn);
  }
  return out;
}

function keccak256Hex(data) {
  return '0x' + keccak256(data).toString('hex');
}

function keccak256ModP(buffers) {
  const data = Buffer.concat(buffers);
  return BigInt('0x' + keccak256(data).toString('hex')) % FIELD_PRIME;
}

if (require.main === module) {
  const vectors = [
    ['', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
    ['abc', '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'],
  ];
  let ok = true;
  for (const [input, expected] of vectors) {
    const got = keccak256(input).toString('hex');
    const pass = got === expected;
    ok = ok && pass;
    console.log(`keccak256(${JSON.stringify(input)}) = ${got} ${pass ? 'PASS' : 'FAIL (expected ' + expected + ')'}`);
  }
  console.log(ok ? 'keccak self-test: ALL PASS' : 'keccak self-test: FAILED');
  process.exit(ok ? 0 : 1);
}

module.exports = { keccak256, keccak256Hex, keccak256ModP, FIELD_PRIME };
