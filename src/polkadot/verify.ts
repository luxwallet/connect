/**
 * Polkadot (Substrate) verifier — wallet login-message signatures.
 *
 * Substrate accounts sign with one of three schemes; the account's key type
 * decides which:
 *   - sr25519           : Schnorrkel/Ristretto255 (the Polkadot default).
 *   - ed25519-substrate : Ed25519 accounts.
 *   - ecdsa-substrate   : secp256k1 accounts (the public key is blake2b-256
 *     hashed to a 32-byte AccountId before SS58 encoding).
 *
 * Two independent checks, both of which must hold (decomplected):
 *
 *  1. Signature: valid over the message a polkadot.js-compatible wallet's
 *     `signRaw({ type: 'bytes' })` actually signs — i.e. the CAIP-122 message
 *     WRAPPED as `<Bytes>…</Bytes>` (the extension wrapper, U8A_WRAP_*). The
 *     wrapped bytes are what `@polkadot/util-crypto`'s `signatureVerify`
 *     checks, dispatching on the key type carried by `proof.publicKey`.
 *  2. Address binding: the claimed SS58 address decodes (with a valid SS58
 *     checksum) to the AccountId that the public key derives — sr25519/ed25519
 *     use the 32-byte public key directly; ecdsa hashes it with blake2b-256.
 *
 * Why a separate entrypoint (and async): sr25519 verification in
 * `@polkadot/util-crypto` is backed by `@scure/sr25519` and requires
 * `cryptoWaitReady()` (a one-time WASM/curve init). The other five chains'
 * verify core stays @noble-pure and synchronous (../verify.ts imports NONE of
 * this). Pure: no I/O, no clock. Fails closed — every error path returns
 * false, nothing throws. Mirrors the Go port go/walletconnect/polkadot.go.
 *
 * Refs:
 *  - https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)
 *  - https://github.com/polkadot-js/common (u8aWrapBytes, signatureVerify)
 *  - https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md
 */
import { blake2b } from '@noble/hashes/blake2b';
import bs58 from 'bs58';
import type { SignedProof, SignatureScheme } from '../types.js';
import { hexToBytes } from '../bytes.js';
import {
  MAX_MESSAGE_LEN,
  MAX_SIGNATURE_LEN,
  MAX_PUBKEY_LEN,
  MAX_ADDRESS_LEN,
  withinLen,
} from '../limits.js';

/** The schemes this verifier handles. */
const SUBSTRATE_SCHEMES: ReadonlySet<SignatureScheme> = new Set<SignatureScheme>([
  'sr25519',
  'ed25519-substrate',
  'ecdsa-substrate',
]);

/** Substrate public-key lengths by scheme (bytes). */
const PUBKEY_LEN: Record<string, number> = {
  sr25519: 32,
  'ed25519-substrate': 32,
  // ecdsa accounts carry the 33-byte compressed secp256k1 point.
  'ecdsa-substrate': 33,
};

/** SS58 context prefix prepended to the checksum preimage: the ASCII 'SS58PRE'. */
const SS58PRE = Uint8Array.from([0x53, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45]);

/** Bitcoin/Base58 alphabet (what SS58 uses — distinct from XRPL's). */
// bs58 already uses this alphabet; kept as documentation only.

/** blake2b-512 of the SS58 checksum preimage. */
function ss58Checksum(preimage: Uint8Array): Uint8Array {
  return blake2b(preimage, { dkLen: 64 });
}

/**
 * Decode an SS58 address to its AccountId, validating the SS58 checksum.
 * Returns null on any malformation (bad base58, unknown prefix length, bad
 * checksum) — fail closed. Supports the common 1-byte address-type prefixes
 * (network ids 0–63) and the 2-byte form (64–16383), each with a 2-byte
 * checksum, which together cover every public Substrate network.
 */
function decodeSs58(address: string): Uint8Array | null {
  if (typeof address !== 'string' || address.length === 0 || address.length > MAX_ADDRESS_LEN) {
    return null;
  }
  let raw: Uint8Array;
  try {
    raw = bs58.decode(address.trim());
  } catch {
    return null;
  }
  // prefix(1|2) || account(32) || checksum(2).
  let prefixLen: number;
  if (raw.length === 0) return null;
  if ((raw[0]! & 0b0100_0000) === 0) {
    // Simple/account-index prefix: a single byte < 64.
    prefixLen = 1;
  } else {
    // Two-byte prefix form.
    prefixLen = 2;
  }
  const checksumLen = 2;
  const accountLen = raw.length - prefixLen - checksumLen;
  if (accountLen !== 32) return null; // only 32-byte AccountIds (all our schemes)

  const body = raw.subarray(0, prefixLen + accountLen);
  const checksum = raw.subarray(prefixLen + accountLen);

  const preimage = new Uint8Array(SS58PRE.length + body.length);
  preimage.set(SS58PRE, 0);
  preimage.set(body, SS58PRE.length);
  const full = ss58Checksum(preimage);
  for (let i = 0; i < checksumLen; i++) {
    if (full[i] !== checksum[i]) return null;
  }
  return raw.subarray(prefixLen, prefixLen + accountLen);
}

/** blake2b-256 (32-byte) AccountId of an ecdsa public key (Substrate convention). */
function accountIdFromEcdsa(pubkey33: Uint8Array): Uint8Array {
  return blake2b(pubkey33, { dkLen: 32 });
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Verify a Polkadot/Substrate login proof. Async because sr25519 needs the
 * one-time `cryptoWaitReady()` init. Fails closed; never throws.
 *
 * The signature is checked over the EXTENSION-WRAPPED message
 * (`<Bytes>{proof.message}</Bytes>`) — what a polkadot.js / Talisman / SubWallet
 * `signRaw({ type: 'bytes' })` produces — and the SS58 address is bound to the
 * declared public key.
 */
export async function verifyPolkadot(proof: SignedProof): Promise<boolean> {
  try {
    if (!SUBSTRATE_SCHEMES.has(proof.scheme)) return false;
    // Bounded presence of every attacker-controlled string before any decode.
    if (!withinLen(proof.publicKey, MAX_PUBKEY_LEN)) return false;
    if (!withinLen(proof.signature, MAX_SIGNATURE_LEN)) return false;
    if (!withinLen(proof.message, MAX_MESSAGE_LEN)) return false;
    if (!withinLen(proof.address, MAX_ADDRESS_LEN)) return false;

    const publicKey = hexToBytes(proof.publicKey);
    if (publicKey.length !== PUBKEY_LEN[proof.scheme]) return false;

    // Lazy-load the Apache-2.0 @polkadot crypto helpers so the verify CORE
    // (../verify.ts, the 5 @noble chains) never pulls them.
    const [{ cryptoWaitReady, signatureVerify }, { u8aWrapBytes, u8aToHex }] = await Promise.all([
      import('@polkadot/util-crypto'),
      import('@polkadot/util'),
    ]);
    await cryptoWaitReady();

    // 1. Address binding: SS58 decodes (valid checksum) to the AccountId the
    //    public key derives.
    const accountId = decodeSs58(proof.address);
    if (accountId == null) return false;
    const expectedAccountId =
      proof.scheme === 'ecdsa-substrate' ? accountIdFromEcdsa(publicKey) : publicKey;
    if (!bytesEqual(accountId, expectedAccountId)) return false;

    // 2. Signature: over the extension-wrapped message bytes, against the
    //    declared public key (signatureVerify dispatches on key type).
    const wrapped = u8aWrapBytes(proof.message);
    const sig = proof.signature.trim();
    const sigArg = sig.startsWith('0x') || sig.startsWith('0X') ? sig : `0x${u8aToHex(hexToBytes(sig)).slice(2)}`;
    const res = signatureVerify(wrapped, sigArg, u8aToHex(publicKey));
    return res.isValid;
  } catch {
    return false;
  }
}
