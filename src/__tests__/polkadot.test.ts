/**
 * Polkadot (Substrate) verifier tests. Mirrors the XRP/TON pattern: an
 * INDEPENDENT wallet-side implementation (real keys via @polkadot/util-crypto,
 * the same Apache-2.0 lib the verifier uses, but driving SIGN here, VERIFY
 * there) mints self-consistent proofs. If the two ever drift, the round-trip
 * "accepts a valid proof" test fails.
 *
 * Covered schemes: sr25519 (default), ed25519-substrate, ecdsa-substrate.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
  cryptoWaitReady,
  sr25519PairFromSeed,
  sr25519Sign,
  ed25519PairFromSeed,
  ed25519Sign,
  secp256k1PairFromSeed,
  secp256k1Sign,
  encodeAddress,
  blake2AsU8a,
} from '@polkadot/util-crypto';
import { u8aWrapBytes, u8aToHex, stringToU8a } from '@polkadot/util';
import { verifyPolkadot } from '../polkadot/verify.js';
import { verifyProofAsync } from '../verify.js';
import { buildSiwxMessage } from '../caip122.js';
import { newChallenge } from '../nonce.js';
import type { SignedProof } from '../types.js';

beforeAll(async () => {
  await cryptoWaitReady();
});

const NOW = 1_700_000_000_000;
const SS58_PREFIX = 42; // generic substrate

function seed(n: number): Uint8Array {
  const s = new Uint8Array(32);
  s[0] = n;
  s[1] = 0xab;
  return s;
}

function mintSr25519(s = seed(1)): { proof: SignedProof; nonce: string } {
  const pair = sr25519PairFromSeed(s);
  const address = encodeAddress(pair.publicKey, SS58_PREFIX);
  const challenge = newChallenge({
    domain: 'hanzo.id',
    uri: 'https://hanzo.id/login',
    nonce: 'dotNonce0001',
    now: NOW,
  });
  const message = buildSiwxMessage({ challenge, address, chain: 'polkadot' });
  // The extension wraps before signing — reproduce that here.
  const signature = u8aToHex(sr25519Sign(u8aWrapBytes(message), pair));
  return {
    nonce: challenge.nonce,
    proof: {
      chain: 'polkadot',
      scheme: 'sr25519',
      address,
      publicKey: u8aToHex(pair.publicKey),
      message,
      signature,
    },
  };
}

function mintEd25519(s = seed(2)): { proof: SignedProof; nonce: string } {
  const pair = ed25519PairFromSeed(s);
  const address = encodeAddress(pair.publicKey, SS58_PREFIX);
  const challenge = newChallenge({
    domain: 'hanzo.id',
    uri: 'https://hanzo.id/login',
    nonce: 'dotEd2550001',
    now: NOW,
  });
  const message = buildSiwxMessage({ challenge, address, chain: 'polkadot' });
  const signature = u8aToHex(ed25519Sign(u8aWrapBytes(message), pair));
  return {
    nonce: challenge.nonce,
    proof: {
      chain: 'polkadot',
      scheme: 'ed25519-substrate',
      address,
      publicKey: u8aToHex(pair.publicKey),
      message,
      signature,
    },
  };
}

function mintEcdsa(s = seed(3)): { proof: SignedProof; nonce: string } {
  const pair = secp256k1PairFromSeed(s);
  // ecdsa AccountId = blake2b-256 of the 33-byte compressed public key.
  const accountId = blake2AsU8a(pair.publicKey, 256);
  const address = encodeAddress(accountId, SS58_PREFIX);
  const challenge = newChallenge({
    domain: 'hanzo.id',
    uri: 'https://hanzo.id/login',
    nonce: 'dotEcdsa0001',
    now: NOW,
  });
  const message = buildSiwxMessage({ challenge, address, chain: 'polkadot' });
  // secp256k1Sign over the wrapped bytes (it blake2-256 prehashes internally,
  // matching what signatureVerify expects for ecdsa).
  const signature = u8aToHex(secp256k1Sign(u8aWrapBytes(message), pair, 'blake2'));
  return {
    nonce: challenge.nonce,
    proof: {
      chain: 'polkadot',
      scheme: 'ecdsa-substrate',
      address,
      publicKey: u8aToHex(pair.publicKey),
      message,
      signature,
    },
  };
}

describe('verifyPolkadot — sr25519 (default)', () => {
  it('accepts a valid proof (full round-trip)', async () => {
    const { proof } = mintSr25519();
    expect(await verifyPolkadot(proof)).toBe(true);
  });

  it('rejects a tampered message', async () => {
    const { proof } = mintSr25519();
    expect(await verifyPolkadot({ ...proof, message: proof.message + ' ' })).toBe(false);
  });

  it('rejects a flipped signature bit', async () => {
    const { proof } = mintSr25519();
    const sig = Uint8Array.from(proof.signature.slice(2).match(/../g)!.map((h) => parseInt(h, 16)));
    sig[0] = (sig[0]! ^ 0x01) & 0xff;
    expect(await verifyPolkadot({ ...proof, signature: u8aToHex(sig) })).toBe(false);
  });

  it('rejects a wrong address (binding failure)', async () => {
    const { proof } = mintSr25519(seed(1));
    const other = mintSr25519(seed(9));
    expect(await verifyPolkadot({ ...proof, address: other.proof.address })).toBe(false);
  });

  it('rejects a mismatched public key', async () => {
    const { proof } = mintSr25519(seed(1));
    const other = mintSr25519(seed(9));
    expect(await verifyPolkadot({ ...proof, publicKey: other.proof.publicKey })).toBe(false);
  });

  it('rejects a corrupted SS58 checksum', async () => {
    const { proof } = mintSr25519();
    // Flip a char in the address to break the SS58 checksum.
    const a = proof.address;
    const bad = a.slice(0, -1) + (a.endsWith('A') ? 'B' : 'A');
    expect(await verifyPolkadot({ ...proof, address: bad })).toBe(false);
  });

  it('fails closed on a missing public key', async () => {
    const { proof } = mintSr25519();
    expect(await verifyPolkadot({ ...proof, publicKey: undefined })).toBe(false);
  });
});

describe('verifyPolkadot — ed25519-substrate', () => {
  it('accepts a valid proof', async () => {
    const { proof } = mintEd25519();
    expect(await verifyPolkadot(proof)).toBe(true);
  });
  it('rejects a tampered message', async () => {
    const { proof } = mintEd25519();
    expect(await verifyPolkadot({ ...proof, message: proof.message + 'x' })).toBe(false);
  });
  it('rejects a wrong address', async () => {
    const { proof } = mintEd25519(seed(2));
    const other = mintEd25519(seed(8));
    expect(await verifyPolkadot({ ...proof, address: other.proof.address })).toBe(false);
  });
});

describe('verifyPolkadot — ecdsa-substrate', () => {
  it('accepts a valid proof (blake2b AccountId binding)', async () => {
    const { proof } = mintEcdsa();
    expect(await verifyPolkadot(proof)).toBe(true);
  });
  it('rejects a tampered message', async () => {
    const { proof } = mintEcdsa();
    expect(await verifyPolkadot({ ...proof, message: proof.message + 'z' })).toBe(false);
  });
  it('rejects a wrong address', async () => {
    const { proof } = mintEcdsa(seed(3));
    const other = mintEcdsa(seed(7));
    expect(await verifyPolkadot({ ...proof, address: other.proof.address })).toBe(false);
  });
});

describe('verifyPolkadot — fail-closed hardening', () => {
  it('rejects an unknown scheme via this verifier', async () => {
    const { proof } = mintSr25519();
    expect(await verifyPolkadot({ ...proof, scheme: 'ed25519' as SignedProof['scheme'] })).toBe(false);
  });
  it('does not throw on garbage input', async () => {
    const garbage = {
      chain: 'polkadot',
      scheme: 'sr25519',
      address: '!!!notss58!!!',
      publicKey: 'nothex',
      message: 'not a siwx message',
      signature: '!!!!',
    } as unknown as SignedProof;
    await expect(verifyPolkadot(garbage)).resolves.toBe(false);
  });
  it('rejects a wrong-length public key', async () => {
    const { proof } = mintSr25519();
    expect(await verifyPolkadot({ ...proof, publicKey: u8aToHex(new Uint8Array(31)) })).toBe(false);
  });
});

describe('verifyProofAsync — Polkadot end-to-end', () => {
  it('accepts a fresh sr25519 proof with full binding/time checks', async () => {
    const { proof, nonce } = mintSr25519();
    const res = await verifyProofAsync(proof, { domain: 'hanzo.id', nonce, now: NOW });
    expect(res.ok).toBe(true);
    expect(res.chain).toBe('polkadot');
    expect(res.address).toBe(proof.address);
  });

  it('rejects a wrong nonce before crypto', async () => {
    const { proof } = mintSr25519();
    const res = await verifyProofAsync(proof, { domain: 'hanzo.id', nonce: 'WRONG', now: NOW });
    expect(res.reason).toBe('nonce-mismatch');
  });

  it('rejects a bad signature with bad-signature', async () => {
    const { proof, nonce } = mintSr25519();
    const res = await verifyProofAsync(
      { ...proof, signature: u8aToHex(stringToU8a('xx').length ? new Uint8Array(64) : new Uint8Array(64)) },
      { domain: 'hanzo.id', nonce, now: NOW },
    );
    expect(res.reason).toBe('bad-signature');
  });

  it('still routes the 5 sync chains correctly (no regression)', async () => {
    // An XRP proof with a deliberately invalid signature must still reach crypto
    // and fail with bad-signature (proves the async path delegates correctly).
    const challenge = newChallenge({
      domain: 'hanzo.id',
      uri: 'https://hanzo.id/login',
      nonce: 'xrpAsync001',
      now: NOW,
    });
    const message = buildSiwxMessage({ challenge, address: 'rXYZ', chain: 'xrp' });
    const proof: SignedProof = {
      chain: 'xrp',
      scheme: 'secp256k1-xrpl',
      address: 'rXYZ',
      message,
      signature: '00',
    };
    const res = await verifyProofAsync(proof, { domain: 'hanzo.id', nonce: 'xrpAsync001', now: NOW });
    expect(res.ok).toBe(false);
  });
});
