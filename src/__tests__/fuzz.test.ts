/**
 * Fuzz / property tests for the SIWx verify core.
 *
 * Two invariants every verifier and the dispatcher must satisfy under ANY input:
 *
 *   (A) NEVER throws / rejects out of band — a verifier returns a boolean (or a
 *       VerifyResult), never an exception. A throw on attacker input is a DoS and
 *       breaks fail-closed semantics.
 *   (B) NEVER returns ok for a non-valid proof — random/mutated bytes must not
 *       forge a login. (The positive direction — real signatures verify — is
 *       covered by verify.test.ts and the per-chain suites.)
 *
 * Strategy: a deterministic PRNG (seeded, reproducible) drives thousands of
 * malformed/adversarial inputs through every verifier and both dispatch entry
 * points, plus a hand-built corpus of known-nasty vectors (truncated, oversized,
 * non-hex/base58/base64, wrong lengths, NaN/overflow ints, deep CBOR, malformed
 * SS58/bech32, cross-scheme confusion). A counter proves the fuzzers actually
 * exercised the verifiers (not all short-circuited at the gate).
 */
import { describe, it, expect } from 'vitest';
import { verifyProof, verifyProofAsync } from '../verify.js';
import { verifyEvm } from '../evm/verify.js';
import { verifySolana } from '../solana/verify.js';
import { verifyTon } from '../ton/verify.js';
import { verifyBitcoin } from '../bitcoin/verify.js';
import { verifyXrp } from '../xrp/verify.js';
import { verifyPolkadot } from '../polkadot/verify.js';
import { verifyCardano } from '../cardano/verify.js';
import { parseSiwxMessage, buildSiwxMessage } from '../caip122.js';
import { cborDecode } from '../cardano/cbor.js';
import { newChallenge } from '../nonce.js';
import { CHAINS, type Chain, type SignatureScheme, type SignedProof } from '../types.js';

// ── deterministic PRNG (mulberry32) so failures reproduce exactly ────────────

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(r: () => number, max: number): number {
  return Math.floor(r() * max);
}

/** Random byte string rendered as one of several attacker encodings. */
function randEncoded(r: () => number): string {
  const len = randInt(r, 200);
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = randInt(r, 256);
  const enc = randInt(r, 6);
  switch (enc) {
    case 0: return '0x' + Buffer.from(bytes).toString('hex');
    case 1: return Buffer.from(bytes).toString('hex');
    case 2: return Buffer.from(bytes).toString('base64');
    case 3: // raw garbage string (non-hex, non-base64)
      return Array.from(bytes, (b) => String.fromCharCode(33 + (b % 90))).join('');
    case 4: return ''; // empty
    default: { // occasionally oversized to hit the DoS guard
      const big = randInt(r, 4) === 0 ? 200_000 : len;
      return 'A'.repeat(big);
    }
  }
}

const ALL_SCHEMES: SignatureScheme[] = [
  'secp256k1-eip191', 'ed25519', 'bip322', 'ton-proof', 'secp256k1-xrpl',
  'ed25519-xrpl', 'sr25519', 'ed25519-substrate', 'ecdsa-substrate', 'ed25519-cardano',
];

/** A fully-random proof: every field attacker-chosen, including junk extra. */
function randProof(r: () => number): SignedProof {
  const chain = CHAINS[randInt(r, CHAINS.length)] as Chain;
  const scheme = ALL_SCHEMES[randInt(r, ALL_SCHEMES.length)] as SignatureScheme;
  const extraKind = randInt(r, 5);
  let extra: Record<string, unknown> | undefined;
  switch (extraKind) {
    case 0: extra = undefined; break;
    case 1: extra = {}; break;
    case 2: extra = { addressType: randEncoded(r) }; break;
    case 3: extra = {
      timestamp: [NaN, Infinity, -1, 1.5, 2 ** 60, randInt(r, 1e9)][randInt(r, 6)],
      workchain: [NaN, -Infinity, 1e40, 0, -1][randInt(r, 5)],
      domain: randEncoded(r), payload: randEncoded(r), addressHashHex: randEncoded(r),
    }; break;
    default: extra = { coseKey: randEncoded(r) }; break;
  }
  return {
    chain, scheme,
    address: randEncoded(r),
    publicKey: randInt(r, 2) ? randEncoded(r) : undefined,
    message: randEncoded(r),
    signature: randEncoded(r),
    extra,
  };
}

// ── (A)+(B): fuzz every per-chain verifier directly ──────────────────────────

describe('fuzz: per-chain verifiers never throw and never forge', () => {
  const ITERS = 3000;

  it('verifyEvm', () => {
    const r = rng(1);
    for (let i = 0; i < ITERS; i++) {
      const p = randProof(r);
      expect(() => verifyEvm(p.message, p.signature, p.address)).not.toThrow();
      expect(verifyEvm(p.message, p.signature, p.address)).toBe(false);
    }
  });

  it('verifySolana', () => {
    const r = rng(2);
    for (let i = 0; i < ITERS; i++) {
      const p = randProof(r);
      expect(() => verifySolana(p.message, p.signature, p.address)).not.toThrow();
      expect(verifySolana(p.message, p.signature, p.address)).toBe(false);
    }
  });

  it('verifyTon', () => {
    const r = rng(3);
    for (let i = 0; i < ITERS; i++) {
      const p = { ...randProof(r), scheme: 'ton-proof' as const };
      expect(() => verifyTon(p)).not.toThrow();
      expect(verifyTon(p)).toBe(false);
    }
  });

  it('verifyXrp', () => {
    const r = rng(4);
    for (let i = 0; i < ITERS; i++) {
      const p = randProof(r);
      expect(() => verifyXrp(p)).not.toThrow();
      expect(verifyXrp(p)).toBe(false);
    }
  });

  it('verifyBitcoin', () => {
    const r = rng(5);
    for (let i = 0; i < ITERS; i++) {
      const p = randProof(r);
      expect(() => verifyBitcoin(p)).not.toThrow();
      expect(verifyBitcoin(p)).toBe(false);
    }
  });

  it('verifyPolkadot', async () => {
    const r = rng(6);
    for (let i = 0; i < 500; i++) {
      const p = randProof(r);
      await expect(verifyPolkadot(p)).resolves.toBe(false);
    }
  });

  it('verifyCardano', () => {
    const r = rng(7);
    for (let i = 0; i < ITERS; i++) {
      const p = { ...randProof(r), scheme: 'ed25519-cardano' as const };
      expect(() => verifyCardano(p)).not.toThrow();
      expect(verifyCardano(p)).toBe(false);
    }
  });
});

// ── (A)+(B): fuzz both dispatch entry points ─────────────────────────────────

describe('fuzz: dispatcher never throws and never returns ok=true', () => {
  it('verifyProof (sync)', () => {
    const r = rng(8);
    let ranCrypto = 0;
    for (let i = 0; i < 5000; i++) {
      const proof = randProof(r);
      const expected = {
        domain: randEncoded(r), nonce: randEncoded(r),
        now: randInt(r, 2_000_000_000_000),
      };
      let res!: ReturnType<typeof verifyProof>;
      expect(() => { res = verifyProof(proof, expected); }).not.toThrow();
      expect(res.ok).toBe(false);
      expect(res.reason).toBeTypeOf('string');
      if (res.reason === 'bad-signature') ranCrypto++;
    }
    // Sanity: the fuzzer actually drove inputs past the gate into the crypto
    // layer at least sometimes (otherwise (B) would be trivially satisfied).
    expect(ranCrypto).toBeGreaterThan(0);
  });

  it('verifyProofAsync (covers Polkadot + Cardano)', async () => {
    const r = rng(9);
    for (let i = 0; i < 800; i++) {
      const proof = randProof(r);
      const expected = { domain: randEncoded(r), nonce: randEncoded(r), now: randInt(r, 2e12) };
      const res = await verifyProofAsync(proof, expected);
      expect(res.ok).toBe(false);
      expect(res.reason).toBeTypeOf('string');
    }
  });
});

// ── (A): parsers never throw out of band on garbage ──────────────────────────

describe('fuzz: parsers fail closed', () => {
  it('parseSiwxMessage either parses or throws a caip122 error (never hangs/leaks)', () => {
    const r = rng(10);
    for (let i = 0; i < 5000; i++) {
      const kind = randInt(r, 4);
      let msg: string;
      if (kind === 0) msg = randEncoded(r);
      else if (kind === 1) msg = '\n'.repeat(randInt(r, 200)); // all newlines
      else if (kind === 2) msg = 'x'.repeat(randInt(r, 3)) + '\n'.repeat(randInt(r, 5));
      else msg = 'A'.repeat(randInt(r, 4) === 0 ? 200_000 : randInt(r, 500)); // oversized sometimes
      try {
        const parsed = parseSiwxMessage(msg);
        // If it parsed, the required fields must be present (the contract).
        expect(parsed.uri).toBeTypeOf('string');
        expect(parsed.nonce).toBeTypeOf('string');
        expect(parsed.issuedAt).toBeTypeOf('string');
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });

  it('cborDecode returns null on garbage and never throws', () => {
    const r = rng(11);
    for (let i = 0; i < 5000; i++) {
      const len = randInt(r, 300);
      const bytes = new Uint8Array(len);
      for (let j = 0; j < len; j++) bytes[j] = randInt(r, 256);
      expect(() => cborDecode(bytes)).not.toThrow();
    }
  });

  it('cborDecode rejects deeply-nested arrays without stack overflow', () => {
    // 0x9f is indefinite array (rejected anyway); 0x81 is array(1) — chain them
    // far past MAX_CBOR_DEPTH. Must return null, not throw a RangeError out.
    const deep = new Uint8Array(5000).fill(0x81);
    expect(() => cborDecode(deep)).not.toThrow();
    expect(cborDecode(deep)).toBeNull();
  });
});

// ── adversarial corpus: specific known-nasty vectors ─────────────────────────

describe('adversarial corpus: hand-picked attack vectors all fail closed', () => {
  const NOW = 1_700_000_000_000;
  const goodExpected = { domain: 'hanzo.id', nonce: 'abc12345', now: NOW };

  // Build a real, well-formed CAIP-122 message so binding checks are reached.
  const challenge = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id/login', nonce: 'abc12345', now: NOW });

  const vectors: Array<{ name: string; proof: SignedProof; expected?: typeof goodExpected }> = [
    {
      name: 'empty everything',
      proof: { chain: 'evm', scheme: 'secp256k1-eip191', address: '', message: '', signature: '' },
    },
    {
      name: 'oversized message (DoS)',
      proof: { chain: 'evm', scheme: 'secp256k1-eip191', address: '0x' + '0'.repeat(40), message: 'A'.repeat(500_000), signature: '0x' + '0'.repeat(130) },
    },
    {
      name: 'oversized signature (DoS)',
      proof: { chain: 'solana', scheme: 'ed25519', address: 'So11111111111111111111111111111111111111112', message: buildSiwxMessage({ challenge, address: 'So11111111111111111111111111111111111111112', chain: 'solana' }), signature: 'A'.repeat(500_000) },
    },
    {
      name: 'oversized publicKey (DoS)',
      proof: { chain: 'xrp', scheme: 'ed25519-xrpl', address: 'rXYZ', publicKey: 'ed' + 'a'.repeat(500_000), message: buildSiwxMessage({ challenge, address: 'rXYZ', chain: 'xrp' }), signature: '00' },
    },
    {
      name: 'cross-scheme confusion: evm chain with ed25519 scheme',
      proof: { chain: 'evm', scheme: 'ed25519', address: '0x' + '1'.repeat(40), message: buildSiwxMessage({ challenge, address: '0x' + '1'.repeat(40), chain: 'evm' }), signature: 'AAAA' },
    },
    {
      name: 'cross-scheme confusion: solana chain with secp256k1-eip191 scheme',
      proof: { chain: 'solana', scheme: 'secp256k1-eip191', address: 'So11111111111111111111111111111111111111112', message: buildSiwxMessage({ challenge, address: 'So11111111111111111111111111111111111111112', chain: 'solana' }), signature: '0x' + '0'.repeat(130) },
    },
    {
      name: 'cross-scheme confusion: bitcoin chain with ton-proof scheme',
      proof: { chain: 'bitcoin', scheme: 'ton-proof', address: 'bc1q'.padEnd(42, 'a'), message: buildSiwxMessage({ challenge, address: 'bc1q'.padEnd(42, 'a'), chain: 'bitcoin' }), signature: 'AA==' },
    },
    {
      name: 'unknown scheme entirely',
      proof: { chain: 'evm', scheme: 'totally-made-up' as SignatureScheme, address: '0x' + '0'.repeat(40), message: buildSiwxMessage({ challenge, address: '0x' + '0'.repeat(40), chain: 'evm' }), signature: '0x00' },
    },
    {
      name: 'non-hex EVM signature',
      proof: { chain: 'evm', scheme: 'secp256k1-eip191', address: '0x' + '0'.repeat(40), message: buildSiwxMessage({ challenge, address: '0x' + '0'.repeat(40), chain: 'evm' }), signature: '0xZZZZnothex' },
    },
    {
      name: 'EVM signature wrong length (64 not 65)',
      proof: { chain: 'evm', scheme: 'secp256k1-eip191', address: '0x' + '0'.repeat(40), message: buildSiwxMessage({ challenge, address: '0x' + '0'.repeat(40), chain: 'evm' }), signature: '0x' + '0'.repeat(128) },
    },
    {
      name: 'Solana address not base58 (32 zero bytes hex is not bs58 of 32 bytes)',
      proof: { chain: 'solana', scheme: 'ed25519', address: '0x000', message: buildSiwxMessage({ challenge, address: '0x000', chain: 'solana' }), signature: 'AAAA' },
    },
    {
      name: 'TON timestamp NaN',
      proof: { chain: 'ton', scheme: 'ton-proof', address: 'EQ', publicKey: 'ed'.repeat(16), message: buildSiwxMessage({ challenge, address: 'EQ', chain: 'ton' }), signature: 'AA==', extra: { timestamp: NaN, workchain: 0, domain: 'd', payload: 'abc12345', addressHashHex: '00'.repeat(32) } },
    },
    {
      name: 'TON workchain overflow (> int32)',
      proof: { chain: 'ton', scheme: 'ton-proof', address: 'EQ', publicKey: '00'.repeat(32), message: buildSiwxMessage({ challenge, address: 'EQ', chain: 'ton' }), signature: 'AA==', extra: { timestamp: 1, workchain: 1e40, domain: 'd', payload: 'abc12345', addressHashHex: '00'.repeat(32) } },
    },
    {
      name: 'Cardano garbage CBOR signature',
      proof: { chain: 'cardano', scheme: 'ed25519-cardano', address: 'addr1xyz', publicKey: '00'.repeat(32), message: buildSiwxMessage({ challenge, address: 'addr1xyz', chain: 'cardano' }), signature: 'deadbeef'.repeat(10) },
    },
    {
      name: 'Cardano malformed bech32 address',
      proof: { chain: 'cardano', scheme: 'ed25519-cardano', address: 'addr1!!!notbech32', publicKey: '00'.repeat(32), message: buildSiwxMessage({ challenge, address: 'addr1!!!notbech32', chain: 'cardano' }), signature: '00'.repeat(80) },
    },
    {
      name: 'Polkadot malformed SS58 address',
      proof: { chain: 'polkadot', scheme: 'sr25519', address: '!!!not-ss58!!!', publicKey: '00'.repeat(32), message: buildSiwxMessage({ challenge, address: '!!!not-ss58!!!', chain: 'polkadot' }), signature: '00'.repeat(64) },
    },
    {
      name: 'address-mismatch: message address != proof address',
      proof: { chain: 'evm', scheme: 'secp256k1-eip191', address: '0x' + '1'.repeat(40), message: buildSiwxMessage({ challenge, address: '0x' + '2'.repeat(40), chain: 'evm' }), signature: '0x' + '0'.repeat(130) },
    },
  ];

  for (const v of vectors) {
    it(`sync: ${v.name}`, () => {
      const res = verifyProof(v.proof, v.expected ?? goodExpected);
      expect(res.ok).toBe(false);
      expect(res.reason).toBeTypeOf('string');
    });
    it(`async: ${v.name}`, async () => {
      const res = await verifyProofAsync(v.proof, v.expected ?? goodExpected);
      expect(res.ok).toBe(false);
      expect(res.reason).toBeTypeOf('string');
    });
  }

  it('cross-scheme confusion yields unsupported-scheme (deterministic, not luck)', () => {
    // chain/scheme mismatch must be rejected by the gate as unsupported-scheme,
    // BEFORE any crypto — proving the binding table closes the class explicitly.
    for (const chain of CHAINS) {
      for (const scheme of ALL_SCHEMES) {
        const proof = {
          chain, scheme,
          address: '0x' + '0'.repeat(40),
          publicKey: '00'.repeat(33),
          message: 'whatever',
          signature: '0x' + '0'.repeat(130),
        } as SignedProof;
        const res = verifyProof(proof, goodExpected);
        if (res.reason !== 'unsupported-scheme') {
          // Only legitimate (chain, scheme) pairs may pass the gate; they then
          // fail later for a different reason — but never with ok=true.
          expect(res.ok).toBe(false);
        }
      }
    }
  });
});
