/**
 * Cardano (CIP-8 / CIP-30 signData) verifier tests.
 *
 * Mirrors the TON/Polkadot pattern: an INDEPENDENT wallet-side implementation
 * (real ed25519 keys via @noble, a hand-rolled CBOR encoder built here on the
 * SIGN side — distinct from the verifier's decoder) mints self-consistent
 * COSE_Sign1 + COSE_Key proofs over the CAIP-122 message. If the sign and
 * verify sides ever drift, the round-trip "accepts a valid proof" test fails.
 *
 * The minted vectors are also the source of the cross-language KAT pinned in
 * go/walletconnect/cardano_test.go (printed by the `KAT vector` test below):
 * TS produces the COSE_Sign1, Go must verify it byte-for-byte.
 */
import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { blake2b } from '@noble/hashes/blake2b';
import { verifyCardano } from '../cardano/verify.js';
import { verifyProofAsync } from '../verify.js';
import { buildSiwxMessage } from '../caip122.js';
import { newChallenge } from '../nonce.js';
import { bytesToHex, utf8ToBytes } from '../bytes.js';
import { bech32Encode } from '../cardano/bech32.js';
import type { SignedProof } from '../types.js';

const NOW = 1_700_000_000_000;

// ── independent CBOR encoder (sign side) ─────────────────────────────────────
// Deliberately separate from src/cardano/cbor.ts so the round-trip is a real
// cross-implementation check, not a tautology.

function head(major: number, n: number): number[] {
  const mt = major << 5;
  if (n < 24) return [mt | n];
  if (n < 0x100) return [mt | 24, n & 0xff];
  if (n < 0x10000) return [mt | 25, (n >> 8) & 0xff, n & 0xff];
  return [mt | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}
function encUint(n: number): number[] {
  return head(0, n);
}
function encNint(n: number): number[] {
  // n is negative; CBOR negint encodes (-1 - n).
  return head(1, -1 - n);
}
function encBytes(b: Uint8Array): number[] {
  return head(2, b.length).concat(Array.from(b));
}
function encText(s: string): number[] {
  const b = utf8ToBytes(s);
  return head(3, b.length).concat(Array.from(b));
}
function bytes(arr: number[]): Uint8Array {
  return Uint8Array.from(arr);
}

/** Encode the COSE protected-headers map { 1: -8 (alg EdDSA), "address": <raw> }. */
function encProtectedMap(addressRaw: Uint8Array): Uint8Array {
  const out: number[] = [];
  out.push(...head(5, 2)); // map(2)
  out.push(...encUint(1)); // key: alg (1)
  out.push(...encNint(-8)); // val: EdDSA (-8)
  out.push(...encText('address')); // key: "address"
  out.push(...encBytes(addressRaw)); // val: raw address bytes
  return bytes(out);
}

/** Encode the COSE Sig_structure (sign side mirror of the verifier's). */
function encSigStructure(protectedSer: Uint8Array, payload: Uint8Array): Uint8Array {
  const out: number[] = [];
  out.push(...head(4, 4)); // array(4)
  out.push(...encText('Signature1'));
  out.push(...encBytes(protectedSer));
  out.push(...encBytes(new Uint8Array(0))); // external_aad
  out.push(...encBytes(payload));
  return bytes(out);
}

/** Encode the full COSE_Sign1 [protected, unprotected, payload, signature]. */
function encCoseSign1(
  protectedSer: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
  hashed = false,
): Uint8Array {
  const out: number[] = [];
  out.push(...head(4, 4)); // array(4)
  out.push(...encBytes(protectedSer)); // protected (serialized bstr)
  // unprotected map { "hashed": bool }
  out.push(...head(5, 1));
  out.push(...encText('hashed'));
  out.push(hashed ? 0xf5 : 0xf4); // true / false
  out.push(...encBytes(payload)); // payload
  out.push(...encBytes(signature)); // signature
  return bytes(out);
}

/** Encode a COSE_Key { 1:1 (OKP), 3:-8 (EdDSA), -1:6 (Ed25519), -2: pub }. */
function encCoseKey(pub: Uint8Array): Uint8Array {
  const out: number[] = [];
  out.push(...head(5, 4)); // map(4)
  out.push(...encUint(1), ...encUint(1)); // kty: OKP
  out.push(...encUint(3), ...encNint(-8)); // alg: EdDSA
  out.push(...encNint(-1), ...encUint(6)); // crv: Ed25519
  out.push(...encNint(-2), ...encBytes(pub)); // x: public key
  return bytes(out);
}

// ── Shelley address (sign side) ──────────────────────────────────────────────

function blake2b224(d: Uint8Array): Uint8Array {
  return blake2b(d, { dkLen: 28 });
}

/** Build a mainnet base address (type 0): header || paymentHash(28) || stakeHash(28). */
function baseAddress(pub: Uint8Array, stakeHash: Uint8Array): { raw: Uint8Array; bech32: string } {
  const header = (0 << 4) | 1; // type 0 (base, key/key), network 1 (mainnet)
  const raw = new Uint8Array(1 + 28 + 28);
  raw[0] = header;
  raw.set(blake2b224(pub), 1);
  raw.set(stakeHash, 1 + 28);
  return { raw, bech32: bech32Encode('addr', raw)! };
}

/** Build a mainnet reward/stake address (type 14): header || stakeHash(28). */
function rewardAddress(pub: Uint8Array): { raw: Uint8Array; bech32: string } {
  const header = (14 << 4) | 1; // type 14 (stake key-hash), network 1
  const raw = new Uint8Array(1 + 28);
  raw[0] = header;
  raw.set(blake2b224(pub), 1);
  return { raw, bech32: bech32Encode('stake', raw)! };
}

function seed(n: number): Uint8Array {
  const s = new Uint8Array(32);
  s[0] = n;
  s[1] = 0xcd;
  return s;
}

interface Minted {
  proof: SignedProof;
  nonce: string;
}

/** Mint a fresh, self-consistent Cardano proof over a base (addr1…) address. */
function mintBase(s = seed(1), nonce = 'adaBase00001'): Minted {
  const priv = s;
  const pub = ed25519.getPublicKey(priv);
  // A distinct stake hash so the base address carries two credentials.
  const stakeHash = blake2b224(utf8ToBytes('stake-' + bytesToHex(pub)));
  const { raw, bech32 } = baseAddress(pub, stakeHash);

  const challenge = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id/login', nonce, now: NOW });
  const message = buildSiwxMessage({ challenge, address: bech32, chain: 'cardano' });
  const payload = utf8ToBytes(message);

  const protectedSer = encProtectedMap(raw);
  const sigStruct = encSigStructure(protectedSer, payload);
  const signature = ed25519.sign(sigStruct, priv);
  const coseSign1 = encCoseSign1(protectedSer, payload, signature);
  const coseKey = encCoseKey(pub);

  return {
    nonce,
    proof: {
      chain: 'cardano',
      scheme: 'ed25519-cardano',
      address: bech32,
      publicKey: bytesToHex(pub),
      message,
      signature: bytesToHex(coseSign1),
      extra: { coseKey: bytesToHex(coseKey) },
    },
  };
}

/** Mint a proof over a reward/stake (stake1…) address. */
function mintReward(s = seed(2), nonce = 'adaStake0001'): Minted {
  const priv = s;
  const pub = ed25519.getPublicKey(priv);
  const { raw, bech32 } = rewardAddress(pub);

  const challenge = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id/login', nonce, now: NOW });
  const message = buildSiwxMessage({ challenge, address: bech32, chain: 'cardano' });
  const payload = utf8ToBytes(message);

  const protectedSer = encProtectedMap(raw);
  const sigStruct = encSigStructure(protectedSer, payload);
  const signature = ed25519.sign(sigStruct, priv);
  const coseSign1 = encCoseSign1(protectedSer, payload, signature);
  const coseKey = encCoseKey(pub);

  return {
    nonce,
    proof: {
      chain: 'cardano',
      scheme: 'ed25519-cardano',
      address: bech32,
      publicKey: bytesToHex(pub),
      message,
      signature: bytesToHex(coseSign1),
      extra: { coseKey: bytesToHex(coseKey) },
    },
  };
}

describe('verifyCardano — base address (addr1…, payment credential)', () => {
  it('accepts a valid proof (full round-trip)', () => {
    const { proof } = mintBase();
    expect(verifyCardano(proof)).toBe(true);
  });

  it('rejects a tampered message', () => {
    const { proof } = mintBase();
    expect(verifyCardano({ ...proof, message: proof.message + ' ' })).toBe(false);
  });

  it('rejects a flipped signature bit', () => {
    const { proof } = mintBase();
    const sig = Uint8Array.from(proof.signature.match(/../g)!.map((h) => parseInt(h, 16)));
    // Flip a bit deep in the COSE_Sign1 (inside the 64-byte ed25519 signature).
    sig[sig.length - 1] = (sig[sig.length - 1]! ^ 0x01) & 0xff;
    expect(verifyCardano({ ...proof, signature: bytesToHex(sig) })).toBe(false);
  });

  it('rejects a wrong address (binding failure)', () => {
    const { proof } = mintBase(seed(1));
    const other = mintBase(seed(9));
    expect(verifyCardano({ ...proof, address: other.proof.address })).toBe(false);
  });

  it('rejects a mismatched public key', () => {
    const { proof } = mintBase(seed(1));
    const other = mintBase(seed(9));
    expect(verifyCardano({ ...proof, publicKey: other.proof.publicKey })).toBe(false);
  });

  it('rejects a corrupted bech32 checksum', () => {
    const { proof } = mintBase();
    const a = proof.address;
    const bad = a.slice(0, -1) + (a.endsWith('q') ? 'p' : 'q');
    expect(verifyCardano({ ...proof, address: bad })).toBe(false);
  });

  it('rejects a COSE_Key whose -2 disagrees with publicKey', () => {
    const { proof } = mintBase(seed(1));
    const other = mintBase(seed(9));
    expect(verifyCardano({ ...proof, extra: { coseKey: other.proof.extra!.coseKey } })).toBe(false);
  });

  it('fails closed on a missing public key', () => {
    const { proof } = mintBase();
    expect(verifyCardano({ ...proof, publicKey: undefined })).toBe(false);
  });

  it('verifies without the optional coseKey extra (publicKey is authoritative)', () => {
    const { proof } = mintBase();
    expect(verifyCardano({ ...proof, extra: undefined })).toBe(true);
  });
});

describe('verifyCardano — reward/stake address (stake1…)', () => {
  it('accepts a valid proof', () => {
    const { proof } = mintReward();
    expect(verifyCardano(proof)).toBe(true);
  });
  it('rejects a tampered message', () => {
    const { proof } = mintReward();
    expect(verifyCardano({ ...proof, message: proof.message + 'x' })).toBe(false);
  });
  it('rejects a wrong address', () => {
    const { proof } = mintReward(seed(2));
    const other = mintReward(seed(8));
    expect(verifyCardano({ ...proof, address: other.proof.address })).toBe(false);
  });
});

describe('verifyCardano — payload binding', () => {
  it('rejects a COSE_Sign1 whose payload is not the CAIP-122 message', () => {
    const { proof } = mintBase();
    // Re-sign a different payload but keep the proof.message — must reject.
    const priv = seed(1);
    const pub = ed25519.getPublicKey(priv);
    const stakeHash = blake2b224(utf8ToBytes('stake-' + bytesToHex(pub)));
    const { raw } = baseAddress(pub, stakeHash);
    const protectedSer = encProtectedMap(raw);
    const wrongPayload = utf8ToBytes('attacker-chosen text');
    const sigStruct = encSigStructure(protectedSer, wrongPayload);
    const signature = ed25519.sign(sigStruct, priv);
    const coseSign1 = encCoseSign1(protectedSer, wrongPayload, signature);
    expect(verifyCardano({ ...proof, signature: bytesToHex(coseSign1) })).toBe(false);
  });

  it('rejects a hashed-payload envelope', () => {
    const priv = seed(3);
    const pub = ed25519.getPublicKey(priv);
    const stakeHash = blake2b224(utf8ToBytes('s'));
    const { raw, bech32 } = baseAddress(pub, stakeHash);
    const challenge = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id/login', nonce: 'adaHashed001', now: NOW });
    const message = buildSiwxMessage({ challenge, address: bech32, chain: 'cardano' });
    const protectedSer = encProtectedMap(raw);
    const payload = blake2b224(utf8ToBytes(message)); // hashed payload
    const sigStruct = encSigStructure(protectedSer, payload);
    const signature = ed25519.sign(sigStruct, priv);
    const coseSign1 = encCoseSign1(protectedSer, payload, signature, /* hashed */ true);
    const coseKey = encCoseKey(pub);
    const proof: SignedProof = {
      chain: 'cardano',
      scheme: 'ed25519-cardano',
      address: bech32,
      publicKey: bytesToHex(pub),
      message,
      signature: bytesToHex(coseSign1),
      extra: { coseKey: bytesToHex(coseKey) },
    };
    expect(verifyCardano(proof)).toBe(false);
  });
});

describe('verifyCardano — fail-closed hardening', () => {
  it('rejects an unknown scheme', () => {
    const { proof } = mintBase();
    expect(verifyCardano({ ...proof, scheme: 'ed25519' as SignedProof['scheme'] })).toBe(false);
  });
  it('does not throw on garbage input', () => {
    const garbage = {
      chain: 'cardano',
      scheme: 'ed25519-cardano',
      address: '!!!notbech32!!!',
      publicKey: 'nothex',
      message: 'not a siwx message',
      signature: '!!!!',
    } as unknown as SignedProof;
    expect(verifyCardano(garbage)).toBe(false);
  });
  it('rejects a wrong-length public key', () => {
    const { proof } = mintBase();
    expect(verifyCardano({ ...proof, publicKey: bytesToHex(new Uint8Array(31)) })).toBe(false);
  });

  it('accepts a valid proof with a LARGE (but legal) message — sig cap must clear the embedded payload', () => {
    // CIP-8 embeds the payload (the CAIP-122 message) inside COSE_Sign1, so the
    // encoded signature is ≈ 2× the message bytes. A large-but-legal message
    // (well under MAX_MESSAGE_LEN=8KiB) produces a signature > the old 4KiB cap;
    // this proves MAX_SIGNATURE_LEN was raised so a real proof is never rejected.
    const priv = seed(9);
    const pub = ed25519.getPublicKey(priv);
    const stakeHash = blake2b224(utf8ToBytes('stake-large'));
    const { raw, bech32 } = baseAddress(pub, stakeHash);
    const nonce = 'adaLarge0001';
    // ~3 KiB statement → message ~3.3 KiB → COSE sig hex ~6.6 KiB (> old 4 KiB).
    const statement = 'I authorize this login. '.repeat(130);
    const challenge = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id/login', statement, nonce, now: NOW });
    const message = buildSiwxMessage({ challenge, address: bech32, chain: 'cardano' });
    const payload = utf8ToBytes(message);
    const protectedSer = encProtectedMap(raw);
    const sigStruct = encSigStructure(protectedSer, payload);
    const signature = ed25519.sign(sigStruct, priv);
    const coseSign1 = encCoseSign1(protectedSer, payload, signature);
    const proof: SignedProof = {
      chain: 'cardano', scheme: 'ed25519-cardano', address: bech32,
      publicKey: bytesToHex(pub), message, signature: bytesToHex(coseSign1),
      extra: { coseKey: bytesToHex(encCoseKey(pub)) },
    };
    // Sanity: this really does exceed the old 4 KiB sig cap (else the test is moot).
    expect(proof.signature.length).toBeGreaterThan(4 * 1024);
    expect(verifyCardano(proof)).toBe(true);
    // And the full dispatcher path accepts it too.
    return verifyProofAsync(proof, { domain: 'hanzo.id', nonce, now: NOW }).then((res) => {
      expect(res.ok).toBe(true);
    });
  });
});

describe('verifyProofAsync — Cardano end-to-end', () => {
  it('accepts a fresh proof with full binding/time checks', async () => {
    const { proof, nonce } = mintBase();
    const res = await verifyProofAsync(proof, { domain: 'hanzo.id', nonce, now: NOW });
    expect(res.ok).toBe(true);
    expect(res.chain).toBe('cardano');
    expect(res.address).toBe(proof.address);
  });

  it('rejects a wrong nonce before crypto', async () => {
    const { proof } = mintBase();
    const res = await verifyProofAsync(proof, { domain: 'hanzo.id', nonce: 'WRONG', now: NOW });
    expect(res.reason).toBe('nonce-mismatch');
  });

  it('returns unsupported-scheme on the SYNC path (routed via async only)', async () => {
    const { proof, nonce } = mintBase();
    const { verifyProof } = await import('../verify.js');
    const res = verifyProof(proof, { domain: 'hanzo.id', nonce, now: NOW });
    expect(res.reason).toBe('unsupported-scheme');
  });
});

// ── cross-language KAT emitter ───────────────────────────────────────────────
// Prints the exact vectors pinned in go/walletconnect/cardano_test.go. Run with
// `VITEST_PRINT_KAT=1 pnpm test cardano` to regenerate the Go KAT after a change.

describe('cross-language KAT vector', () => {
  it('emits deterministic vectors for the Go port', () => {
    const base = mintBase(seed(1), 'adaBase00001');
    const reward = mintReward(seed(2), 'adaStake0001');
    for (const [name, m] of [['base', base], ['reward', reward]] as const) {
      // Deterministic given the fixed seed + NOW, so the Go KAT can pin them.
      expect(verifyCardano(m.proof)).toBe(true);
      if (process.env.VITEST_PRINT_KAT) {
        // eslint-disable-next-line no-console
        console.log(`KAT ${name}`, JSON.stringify({
          scheme: m.proof.scheme,
          address: m.proof.address,
          publicKey: m.proof.publicKey,
          message: m.proof.message,
          signature: m.proof.signature,
          coseKey: m.proof.extra!.coseKey,
          nonce: m.nonce,
        }));
      }
    }
  });
});
