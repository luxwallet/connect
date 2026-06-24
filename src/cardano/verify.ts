/**
 * Cardano verifier — CIP-8 / CIP-30 `signData` (COSE_Sign1 + COSE_Key, ed25519).
 *
 * A CIP-30 wallet's `api.signData(addrHex, payloadHex)` returns
 *   { signature: cbor<COSE_Sign1>, key: cbor<COSE_Key> }.
 * The connector renders the CAIP-122 login message, has the wallet sign it, and
 * packs the result into a {@link SignedProof}:
 *   scheme    'ed25519-cardano'
 *   address   the bech32 address (addr1…/stake1…)
 *   publicKey the COSE_Key's ed25519 public key (hex; 32B raw or 64B extended)
 *   signature the COSE_Sign1 cbor (hex)
 *   message   the CAIP-122 string (== the COSE_Sign1 payload, non-hashed)
 *   extra.coseKey  the COSE_Key cbor (hex)  [optional; publicKey is authoritative]
 *
 * Two independent checks, both must hold (decomplected, like Polkadot):
 *
 *  1. Signature: ed25519 over the COSE `Sig_structure`
 *       [ "Signature1", protected, external_aad(empty), payload ]
 *     reconstructed from the COSE_Sign1 CBOR. The payload inside the COSE_Sign1
 *     MUST equal the proof's CAIP-122 message bytes (non-hashed signing), so a
 *     wallet cannot sign one thing and present another.
 *  2. Address binding: blake2b-224(pubkey[0..32]) == the 28-byte key credential
 *     embedded in the bech32 address (payment credential for addr1…/enterprise,
 *     stake credential for stake1…). The address's bech32 checksum must be valid.
 *
 * Pure: no I/O, no clock, no network. Fails closed — every error path returns
 * false; never throws. @noble (ed25519, blake2b) + inline CBOR/bech32 only —
 * zero copyleft, zero WASM, fully synchronous. Mirrors go/walletconnect/cardano.go.
 *
 * Refs:
 *  - CIP-8  Message Signing:  https://cips.cardano.org/cip/CIP-0008
 *  - CIP-30 signData:         https://cips.cardano.org/cip/CIP-0030
 *  - CIP-19 Address format:   https://cips.cardano.org/cip/CIP-0019
 *  - RFC 9052 (COSE_Sign1):   https://datatracker.ietf.org/doc/rfc9052/
 */
import { ed25519 } from '@noble/curves/ed25519';
import { blake2b } from '@noble/hashes/blake2b';
import type { SignedProof } from '../types.js';
import { hexToBytes, utf8ToBytes } from '../bytes.js';
import { cborDecode, buildSigStructure, type CborMap, type CborValue } from './cbor.js';
import { bech32Decode } from './bech32.js';
import {
  MAX_MESSAGE_LEN,
  MAX_SIGNATURE_LEN,
  MAX_PUBKEY_LEN,
  MAX_ADDRESS_LEN,
  MAX_EXTRA_STRING_LEN,
  withinLen,
} from '../limits.js';

/** ed25519: 32-byte public key, 64-byte signature, 28-byte blake2b key hash. */
const ED25519_PUBKEY_LEN = 32;
const ED25519_SIG_LEN = 64;
const KEY_HASH_LEN = 28; // blake2b-224

/** COSE_Key map key for the public key bytes (x coordinate), per RFC 9052. */
const COSE_KEY_X = -2;

/** blake2b-224 (28-byte) hash — the Cardano key-credential function. */
function blake2b224(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: KEY_HASH_LEN });
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Extract the 28-byte key credential that must equal blake2b-224(pubkey) from a
 * decoded Cardano address. Returns null for address types this login flow does
 * not bind (script-credential addresses, Byron, malformed). The credential is:
 *   - base addresses (type 0..3): the PAYMENT credential (first 28B after header)
 *   - enterprise   (type 6,7):    the PAYMENT credential
 *   - reward/stake (type 14,15):  the STAKE credential
 * Key-hash vs script-hash is encoded in the low bit(s) of the type nibble; only
 * key-hash credentials can match an ed25519 public key, so script types → null.
 */
function keyCredentialFromAddress(hrp: string, data: Uint8Array): Uint8Array | null {
  if (data.length < 1 + KEY_HASH_LEN) return null;
  const header = data[0]!;
  const type = header >> 4;

  // Payment-credential address families (addr1… / addr_test1…).
  if (hrp === 'addr' || hrp === 'addr_test') {
    switch (type) {
      // Base: payment-key + stake-* . type 0 = key/key, 1 = script/key,
      //       2 = key/script, 3 = script/script. Only payment=KEY binds an
      //       ed25519 key, i.e. type 0 or 2.
      case 0:
      case 2:
        if (data.length < 1 + 2 * KEY_HASH_LEN) return null;
        return data.subarray(1, 1 + KEY_HASH_LEN);
      // Enterprise: payment only. type 6 = key, 7 = script.
      case 6:
        if (data.length !== 1 + KEY_HASH_LEN) return null;
        return data.subarray(1, 1 + KEY_HASH_LEN);
      default:
        return null; // pointer (4/5), script-payment (1/3/7), Byron, etc.
    }
  }

  // Stake/reward address family (stake1… / stake_test1…).
  if (hrp === 'stake' || hrp === 'stake_test') {
    // type 14 = stake key-hash, 15 = stake script-hash. Only 14 binds a key.
    if (type === 14) {
      if (data.length !== 1 + KEY_HASH_LEN) return null;
      return data.subarray(1, 1 + KEY_HASH_LEN);
    }
    return null;
  }

  return null;
}

/** Read the COSE_Key public key (map key -2). Returns null if absent/!bytes. */
function publicKeyFromCoseKey(coseKeyHex: string): Uint8Array | null {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(coseKeyHex);
  } catch {
    return null;
  }
  const decoded = cborDecode(bytes);
  if (!(decoded instanceof Map)) return null;
  const x = (decoded as CborMap).get(COSE_KEY_X);
  return x instanceof Uint8Array ? x : null;
}

/** Narrow a CBOR value to a definite COSE_Sign1 quad. */
function asCoseSign1(
  v: CborValue | null,
): { protectedSer: Uint8Array; unprotected: CborMap; payload: Uint8Array | null; signature: Uint8Array } | null {
  if (!Array.isArray(v) || v.length !== 4) return null;
  const [p, u, pay, sig] = v;
  if (!(p instanceof Uint8Array)) return null; // protected: serialized bstr
  if (!(u instanceof Map)) return null; // unprotected: map
  if (!(sig instanceof Uint8Array)) return null; // signature: bstr
  const payload = pay instanceof Uint8Array ? pay : pay === null ? null : undefined;
  if (payload === undefined) return null; // payload must be bstr or null
  return { protectedSer: p, unprotected: u as CborMap, payload, signature: sig };
}

/**
 * Verify a Cardano CIP-8/CIP-30 login proof (ed25519 over COSE_Sign1) with
 * blake2b-224 address binding. Both the signature check and the address binding
 * must pass. Fails closed on any decode error, length mismatch, hashed payload,
 * or scheme mismatch — never throws.
 *
 * The public key is taken from `proof.publicKey` (authoritative). If
 * `proof.extra.coseKey` is present its `-2` key MUST equal `proof.publicKey`
 * (defence in depth — a wallet cannot present one key and prove another).
 */
export function verifyCardano(proof: SignedProof): boolean {
  try {
    // Scheme + bounded presence of every attacker-controlled string. Bounds cap
    // the COSE/CBOR decode + hashing and make this exported verifier safe when
    // called directly (the dispatcher also gates).
    if (proof.scheme !== 'ed25519-cardano') return false;
    if (!withinLen(proof.publicKey, MAX_PUBKEY_LEN)) return false;
    if (!withinLen(proof.signature, MAX_SIGNATURE_LEN)) return false;
    if (!withinLen(proof.message, MAX_MESSAGE_LEN)) return false;
    if (!withinLen(proof.address, MAX_ADDRESS_LEN)) return false;

    // The ed25519 public key is the first 32 bytes (extended bip32 keys append a
    // 32-byte chaincode; we hash/verify with the bare ed25519 key only).
    const fullPub = hexToBytes(proof.publicKey);
    if (fullPub.length !== ED25519_PUBKEY_LEN && fullPub.length !== 2 * ED25519_PUBKEY_LEN) {
      return false;
    }
    const pub = fullPub.subarray(0, ED25519_PUBKEY_LEN);

    // Defence in depth: when a COSE_Key is carried, its -2 must equal publicKey.
    const coseKeyHex = (proof.extra as Record<string, unknown> | undefined)?.coseKey;
    if (typeof coseKeyHex === 'string' && coseKeyHex.length > 0) {
      if (coseKeyHex.length > MAX_EXTRA_STRING_LEN) return false;
      const fromKey = publicKeyFromCoseKey(coseKeyHex);
      if (fromKey === null) return false;
      if (!bytesEqual(fromKey.subarray(0, ED25519_PUBKEY_LEN), pub)) return false;
    }

    // --- 1. Address binding: blake2b-224(pubkey) == key credential. ---
    const addr = bech32Decode(proof.address.trim());
    if (addr === null) return false;
    const credential = keyCredentialFromAddress(addr.hrp, addr.data);
    if (credential === null) return false;
    if (!bytesEqual(blake2b224(pub), credential)) return false;

    // --- 2. Signature over the reconstructed COSE Sig_structure. ---
    const cose = asCoseSign1(cborDecode(hexToBytes(proof.signature)));
    if (cose === null) return false;

    // Reject hashed payloads: our login flow signs the message verbatim, so a
    // `hashed: true` envelope would mean the signed bytes are NOT the message
    // and the binding below would be meaningless. Fail closed.
    if (cose.unprotected.get('hashed') === true) return false;

    // Bind the signed payload to the CAIP-122 message: the COSE_Sign1 payload
    // MUST equal the proof's message bytes. (Some wallets sign with a detached
    // payload, in which case it is supplied externally; here we require it to be
    // embedded and to match — anything else is rejected.)
    const messageBytes = utf8ToBytes(proof.message);
    if (cose.payload === null) return false;
    if (!bytesEqual(cose.payload, messageBytes)) return false;

    if (cose.signature.length !== ED25519_SIG_LEN) return false;

    const sigStruct = buildSigStructure(cose.protectedSer, new Uint8Array(0), cose.payload);
    return ed25519.verify(cose.signature, sigStruct, pub);
  } catch {
    return false;
  }
}
