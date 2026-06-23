import { describe, it, expect } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import bs58 from 'bs58';
import { verifyEvm, eip191Digest, addressFromPublicKey } from '../evm/verify.js';
import { verifySolana } from '../solana/verify.js';
import { verifyProof } from '../verify.js';
import { buildSiwxMessage } from '../caip122.js';
import { newChallenge } from '../nonce.js';
import { bytesToHex, bytesToBase64, utf8ToBytes } from '../bytes.js';
import type { SignedProof } from '../types.js';

// --- test signers (produce real signatures the verifier must accept) ---

function evmSign(message: string) {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(priv, false);
  const address = addressFromPublicKey(pub);
  const sig = secp256k1.sign(eip191Digest(message), priv);
  const full = new Uint8Array(65);
  full.set(sig.toCompactRawBytes(), 0);
  full[64] = (sig.recovery ?? 0) + 27;
  return { address, signature: '0x' + bytesToHex(full) };
}

function solanaSign(message: string) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = bs58.encode(pub);
  const signature = bytesToBase64(ed25519.sign(utf8ToBytes(message), priv));
  return { address, signature };
}

describe('EVM EIP-191 verify', () => {
  it('accepts a valid signature', () => {
    const message = 'hello hanzo';
    const { address, signature } = evmSign(message);
    expect(verifyEvm(message, signature, address)).toBe(true);
  });
  it('is case-insensitive on the address', () => {
    const message = 'hello';
    const { address, signature } = evmSign(message);
    expect(verifyEvm(message, signature, address.toUpperCase().replace('0X', '0x'))).toBe(true);
  });
  it('rejects a tampered message', () => {
    const { address, signature } = evmSign('original');
    expect(verifyEvm('tampered', signature, address)).toBe(false);
  });
  it('rejects a wrong address', () => {
    const { signature } = evmSign('m');
    expect(verifyEvm('m', signature, '0x0000000000000000000000000000000000000000')).toBe(false);
  });
});

describe('Solana ed25519 verify', () => {
  it('accepts a valid signature', () => {
    const message = 'hello solana';
    const { address, signature } = solanaSign(message);
    expect(verifySolana(message, signature, address)).toBe(true);
  });
  it('rejects a tampered message', () => {
    const { address, signature } = solanaSign('original');
    expect(verifySolana('tampered', signature, address)).toBe(false);
  });
  it('rejects a wrong address', () => {
    const { signature } = solanaSign('m');
    const other = bs58.encode(ed25519.getPublicKey(ed25519.utils.randomPrivateKey()));
    expect(verifySolana('m', signature, other)).toBe(false);
  });
});

describe('verifyProof end-to-end', () => {
  const now = 1_700_000_000_000;
  const base = { domain: 'hanzo.id', uri: 'https://hanzo.id/login', nonce: 'abc12345', now };

  it('accepts a fresh EVM proof', () => {
    const challenge = newChallenge(base);
    // EVM: derive the address from the key, embed it in the message, then sign.
    const priv = secp256k1.utils.randomPrivateKey();
    const address = addressFromPublicKey(secp256k1.getPublicKey(priv, false));
    const message = buildSiwxMessage({ challenge, address, chain: 'evm' });
    const sig = secp256k1.sign(eip191Digest(message), priv);
    const full = new Uint8Array(65);
    full.set(sig.toCompactRawBytes(), 0);
    full[64] = (sig.recovery ?? 0) + 27;
    const proof: SignedProof = {
      chain: 'evm', scheme: 'secp256k1-eip191', address, message,
      signature: '0x' + bytesToHex(full),
    };
    const res = verifyProof(proof, { domain: 'hanzo.id', nonce: 'abc12345', now });
    expect(res.ok).toBe(true);
    expect(res.address).toBe(address);
  });

  it('accepts a fresh Solana proof', () => {
    const challenge = newChallenge(base);
    // address is the pubkey; sign the message that embeds that address
    const priv = ed25519.utils.randomPrivateKey();
    const address = bs58.encode(ed25519.getPublicKey(priv));
    const message = buildSiwxMessage({ challenge, address, chain: 'solana' });
    const signature = bytesToBase64(ed25519.sign(utf8ToBytes(message), priv));
    const proof: SignedProof = { chain: 'solana', scheme: 'ed25519', address, message, signature };
    expect(verifyProof(proof, { domain: 'hanzo.id', nonce: 'abc12345', now }).ok).toBe(true);
  });

  it('rejects wrong nonce / domain', () => {
    const challenge = newChallenge(base);
    const address = bs58.encode(ed25519.getPublicKey(ed25519.utils.randomPrivateKey()));
    const message = buildSiwxMessage({ challenge, address, chain: 'solana' });
    const proof: SignedProof = { chain: 'solana', scheme: 'ed25519', address, message, signature: 'AAAA' };
    expect(verifyProof(proof, { domain: 'hanzo.id', nonce: 'WRONG', now }).reason).toBe('nonce-mismatch');
    expect(verifyProof(proof, { domain: 'evil.com', nonce: 'abc12345', now }).reason).toBe('domain-mismatch');
  });

  it('rejects an expired proof', () => {
    const challenge = newChallenge({ ...base, ttlSeconds: 60 });
    const priv = ed25519.utils.randomPrivateKey();
    const address = bs58.encode(ed25519.getPublicKey(priv));
    const message = buildSiwxMessage({ challenge, address, chain: 'solana' });
    const signature = bytesToBase64(ed25519.sign(utf8ToBytes(message), priv));
    const proof: SignedProof = { chain: 'solana', scheme: 'ed25519', address, message, signature };
    // now is 1h after issuance, well past 60s ttl + skew
    const res = verifyProof(proof, { domain: 'hanzo.id', nonce: 'abc12345', now: now + 3_600_000 });
    expect(res.reason).toBe('expired');
  });

  it('fails closed on not-yet-implemented schemes', () => {
    const challenge = newChallenge(base);
    const message = buildSiwxMessage({ challenge, address: 'rXYZ', chain: 'xrp' });
    const proof: SignedProof = { chain: 'xrp', scheme: 'secp256k1-xrpl', address: 'rXYZ', message, signature: '00' };
    expect(verifyProof(proof, { domain: 'hanzo.id', nonce: 'abc12345', now }).reason).toBe('unsupported-scheme');
  });
});
