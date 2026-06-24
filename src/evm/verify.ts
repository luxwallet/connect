/**
 * EVM verifier — EIP-191 `personal_sign` over the CAIP-122 message.
 *
 * Recovers the secp256k1 public key from the signature, derives the Ethereum
 * address (keccak256 of the uncompressed pubkey, last 20 bytes), and compares
 * it case-insensitively to the claimed address. No viem dependency — pure
 * @noble so this mirrors 1:1 in the Go port.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { utf8ToBytes, concatBytes, hexToBytes, bytesToHex } from '../bytes.js';
import { MAX_MESSAGE_LEN, MAX_SIGNATURE_LEN, MAX_ADDRESS_LEN } from '../limits.js';

/** keccak256(\x19Ethereum Signed Message:\n<len><msg>). */
export function eip191Digest(message: string): Uint8Array {
  const msg = utf8ToBytes(message);
  const prefix = utf8ToBytes(`\x19Ethereum Signed Message:\n${msg.length}`);
  return keccak_256(concatBytes(prefix, msg));
}

/** Lowercased 0x-address derived from an uncompressed (65-byte) public key. */
export function addressFromPublicKey(pubUncompressed: Uint8Array): string {
  // Drop the 0x04 prefix → 64 bytes, hash, take last 20.
  const body = pubUncompressed.length === 65 ? pubUncompressed.slice(1) : pubUncompressed;
  const hash = keccak_256(body);
  return '0x' + bytesToHex(hash.slice(-20));
}

/**
 * Verify an EIP-191 signature. Returns the recovered lowercased address, or
 * null if the signature is malformed / unrecoverable.
 */
export function recoverEvmAddress(message: string, signature: string): string | null {
  try {
    // Bound inputs before hashing the message / decoding the sig (DoS guard;
    // also makes this exported helper safe when called outside the dispatcher).
    if (typeof message !== 'string' || message.length > MAX_MESSAGE_LEN) return null;
    if (typeof signature !== 'string' || signature.length > MAX_SIGNATURE_LEN) return null;
    const sig = hexToBytes(signature);
    if (sig.length !== 65) return null;
    const compact = sig.slice(0, 64);
    let v = sig[64]!;
    // Accept 27/28 (Ethereum) and raw 0/1 recovery ids.
    if (v >= 27) v -= 27;
    if (v !== 0 && v !== 1) return null;
    const digest = eip191Digest(message);
    const recovered = secp256k1.Signature.fromCompact(compact)
      .addRecoveryBit(v)
      .recoverPublicKey(digest);
    return addressFromPublicKey(recovered.toRawBytes(false));
  } catch {
    return null;
  }
}

/** True iff `signature` over `message` was produced by `address`. */
export function verifyEvm(message: string, signature: string, address: string): boolean {
  if (typeof address !== 'string' || address.length === 0 || address.length > MAX_ADDRESS_LEN) {
    return false;
  }
  const recovered = recoverEvmAddress(message, signature);
  if (recovered == null) return false;
  return recovered.toLowerCase() === address.trim().toLowerCase();
}
