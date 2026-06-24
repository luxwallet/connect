/**
 * TON verifier — TON Connect `ton_proof` (ed25519).
 *
 * Unlike text-signing chains, TON signs a structured `ton_proof` envelope, not
 * the CAIP-122 string. The connector carries the envelope in `proof.extra` and
 * the wallet public key in `proof.publicKey`; this verifier reconstructs the
 * ton_proof signing message exactly as the TON Connect spec defines it, checks
 * the ed25519 signature over the double-SHA-256 digest, and binds the envelope
 * to the CAIP-122 login message (nonce == payload, address == signer).
 *
 * Reference (TON Connect ton_proof):
 *   message = "ton-proof-item-v2/"
 *           ‖ int32BE(workchain)
 *           ‖ addressHash(32)
 *           ‖ uint32LE(len(domain))
 *           ‖ domain
 *           ‖ uint64LE(timestamp)
 *           ‖ payload
 *   signed  = sha256( 0xffff ‖ "ton-connect" ‖ sha256(message) )
 *   ok      = ed25519.verify(signature, signed, publicKey)
 *
 * Pure: no I/O, no network, no clock. Fails closed — any malformed or missing
 * field returns false; never throws.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import type { SignedProof } from '../types.js';
import { parseSiwxMessage } from '../caip122.js';
import { hexToBytes, base64ToBytes, utf8ToBytes, concatBytes } from '../bytes.js';
import {
  MAX_MESSAGE_LEN,
  MAX_SIGNATURE_LEN,
  MAX_PUBKEY_LEN,
  MAX_ADDRESS_LEN,
  MAX_EXTRA_STRING_LEN,
  withinLen,
} from '../limits.js';

/** ton_proof static prefixes (TON Connect v2). */
const PROOF_PREFIX = utf8ToBytes('ton-proof-item-v2/');
const CONNECT_PREFIX = utf8ToBytes('ton-connect');

/** ed25519 public keys are 32 bytes; signatures are 64 bytes; addr hash 32. */
const ED25519_PUBKEY_LEN = 32;
const ED25519_SIG_LEN = 64;
const ADDR_HASH_LEN = 32;

/** The `extra` envelope a TON connector attaches to a ton_proof. */
interface TonProofExtra {
  timestamp: number;
  domain: string;
  payload: string;
  workchain: number;
  addressHashHex: string;
}

/** Narrow `proof.extra` to the ton_proof envelope, validating field shapes. */
function readExtra(extra: unknown): TonProofExtra | null {
  if (extra == null || typeof extra !== 'object') return null;
  const e = extra as Record<string, unknown>;
  const { timestamp, domain, payload, workchain, addressHashHex } = e;
  // timestamp: a finite, non-negative integer number of unix seconds.
  if (typeof timestamp !== 'number' || !Number.isInteger(timestamp) || timestamp < 0) return null;
  // workchain: a finite integer that must fit a signed 32-bit field (int32BE in
  // the proof message). Reject out-of-range so setInt32 can't silently wrap.
  if (typeof workchain !== 'number' || !Number.isInteger(workchain)) return null;
  if (workchain < -0x80000000 || workchain > 0x7fffffff) return null;
  // domain/payload/addressHashHex: strings, each bounded (attacker-controlled,
  // feed the hash pre-image / hex decode). Empty domain/payload is legitimate
  // (payload binds to the nonce, checked later), so allow length 0 here.
  if (typeof domain !== 'string' || domain.length > MAX_EXTRA_STRING_LEN) return null;
  if (typeof payload !== 'string' || payload.length > MAX_EXTRA_STRING_LEN) return null;
  if (typeof addressHashHex !== 'string' || addressHashHex.length > MAX_EXTRA_STRING_LEN) return null;
  return { timestamp, domain, payload, workchain, addressHashHex };
}

/**
 * Reconstruct the ton_proof message body that the wallet hashed:
 *   "ton-proof-item-v2/" ‖ int32BE(wc) ‖ addrHash ‖ uint32LE(|domain|) ‖ domain
 *                        ‖ uint64LE(ts) ‖ payload
 *
 * Integer widths/endianness are spec-exact:
 *   - workchain: 4 bytes, big-endian, SIGNED (so -1 → 0xFFFFFFFF).
 *   - domain length: 4 bytes, little-endian, the UTF-8 BYTE length.
 *   - timestamp: 8 bytes, little-endian (BigInt to span > 2^53 safely).
 */
function buildProofMessage(
  workchain: number,
  addressHash: Uint8Array,
  domainBytes: Uint8Array,
  timestamp: number,
  payloadBytes: Uint8Array,
): Uint8Array {
  // workchain — int32 big-endian (signed two's-complement via setInt32).
  const wc = new Uint8Array(4);
  new DataView(wc.buffer).setInt32(0, workchain, /* littleEndian */ false);

  // domain length — uint32 little-endian over the UTF-8 byte length.
  const dlen = new Uint8Array(4);
  new DataView(dlen.buffer).setUint32(0, domainBytes.length, /* littleEndian */ true);

  // timestamp — uint64 little-endian.
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(timestamp), /* littleEndian */ true);

  return concatBytes(PROOF_PREFIX, wc, addressHash, dlen, domainBytes, ts, payloadBytes);
}

/** TON Connect's full pre-image and the double hash that ed25519 actually signs. */
function proofDigest(message: Uint8Array): Uint8Array {
  // fullMsg = 0xff 0xff ‖ "ton-connect" ‖ sha256(message)
  const fullMsg = concatBytes(Uint8Array.of(0xff, 0xff), CONNECT_PREFIX, sha256(message));
  return sha256(fullMsg);
}

/**
 * Verify a TON Connect `ton_proof` login proof.
 *
 * @returns true iff the ed25519 signature is valid over the reconstructed
 *   ton_proof digest AND the envelope is bound to the CAIP-122 message
 *   (nonce == payload, address == signer). Any other condition → false.
 */
export function verifyTon(proof: SignedProof): boolean {
  try {
    // --- 0. Structural presence + bounds: scheme, public key, signature,
    // message, address, envelope. Bounds make this exported verifier safe when
    // called directly (the dispatcher also gates) and cap pre-crypto work. ---
    if (proof.scheme !== 'ton-proof') return false;
    if (!withinLen(proof.publicKey, MAX_PUBKEY_LEN)) return false;
    if (!withinLen(proof.signature, MAX_SIGNATURE_LEN)) return false;
    if (!withinLen(proof.message, MAX_MESSAGE_LEN)) return false;
    if (!withinLen(proof.address, MAX_ADDRESS_LEN)) return false;

    const extra = readExtra(proof.extra);
    if (extra === null) return false;

    // --- 1. Binding to the CAIP-122 login message (anti-replay, anti-phishing).
    // parseSiwxMessage throws on malformed input; the try/catch fails closed.
    const parsed = parseSiwxMessage(proof.message);
    // The signed payload MUST be the server-minted nonce carried in the SIWx msg.
    if (parsed.nonce !== extra.payload) return false;
    // The signer MUST be the address embedded in the message.
    if (parsed.address !== proof.address) return false;

    // --- 2. Decode + length-check the fixed-width cryptographic material. ---
    const publicKey = hexToBytes(proof.publicKey);
    if (publicKey.length !== ED25519_PUBKEY_LEN) return false;

    const signature = base64ToBytes(proof.signature);
    if (signature.length !== ED25519_SIG_LEN) return false;

    const addressHash = hexToBytes(extra.addressHashHex);
    if (addressHash.length !== ADDR_HASH_LEN) return false;

    // --- 3. Reconstruct the ton_proof message and the digest the wallet signed.
    const domainBytes = utf8ToBytes(extra.domain);
    const payloadBytes = utf8ToBytes(extra.payload);
    const message = buildProofMessage(
      extra.workchain,
      addressHash,
      domainBytes,
      extra.timestamp,
      payloadBytes,
    );
    const digest = proofDigest(message);

    // --- 4. ed25519 signature check over the 32-byte digest. ---
    return ed25519.verify(signature, digest, publicKey);
  } catch {
    // Bad hex/base64, malformed SIWx, etc. — fail closed.
    return false;
  }
}
