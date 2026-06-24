/**
 * XRP (XRP Ledger) verifier — wallet login-message signatures.
 *
 * XRPL accounts use either a secp256k1 or an ed25519 keypair. The connector
 * carries the public key in `proof.publicKey` (33 bytes in XRPL's canonical
 * form). This verifier does two independent checks, both of which must hold:
 *
 *  1. Signature: the signature is valid over the CAIP-122 message under the
 *     declared key, using XRPL's signing convention for the scheme.
 *       - ed25519-xrpl : raw EdDSA over the UTF-8 message bytes.
 *       - secp256k1-xrpl : ECDSA over the "sha512half" digest
 *         (first 32 bytes of SHA-512 of the message), DER-encoded.
 *  2. Address binding: the public key derives the claimed r-address via the
 *     standard XRPL AccountID derivation (RIPEMD160(SHA256(pubkey)) under the
 *     0x00 account prefix, base58check with the XRPL alphabet).
 *
 * Decomplected: signature verification and address binding are separate,
 * each complete on its own. Fails closed — every error path returns false,
 * nothing throws. Pure: no I/O, no clock. Mirrors 1:1 in the Go port.
 *
 * Refs:
 *  - https://xrpl.org/cryptographic-keys.html (key prefixes, AccountID)
 *  - https://xrpl.org/base58-encodings.html (XRPL base58 alphabet, type prefix)
 *  - https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { ripemd160 } from '@noble/hashes/ripemd160';
import type { SignedProof } from '../types.js';
import { hexToBytes, decodeSignature, utf8ToBytes, concatBytes } from '../bytes.js';
import {
  MAX_MESSAGE_LEN,
  MAX_SIGNATURE_LEN,
  MAX_PUBKEY_LEN,
  MAX_ADDRESS_LEN,
  withinLen,
} from '../limits.js';

/** XRPL's base58 alphabet (NOT the Bitcoin/IPFS alphabet — different order). */
const XRPL_ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

/** Account address type prefix byte (the leading 'r' once base58-encoded). */
const ACCOUNT_ID_PREFIX = 0x00;

/** XRPL public keys are always 33 bytes: a 1-byte family tag + 32-byte key. */
const PUBKEY_LEN = 33;
const ED25519_PREFIX = 0xed;
const ED25519_SIG_LEN = 64;

/** XRPL "sha512half": the first half (32 bytes) of SHA-512 over the input. */
function sha512Half(data: Uint8Array): Uint8Array {
  return sha512(data).slice(0, 32);
}

/**
 * Base58Check encode using the XRPL alphabet. `payload` is the version-prefixed
 * data; a 4-byte double-SHA256 checksum is appended before encoding. Pure
 * big-integer base conversion so it matches the Go port byte-for-byte.
 */
function base58CheckXrpl(payload: Uint8Array): string {
  const checksum = sha256(sha256(payload)).slice(0, 4);
  const full = concatBytes(payload, checksum);

  // Big-endian base-256 → base-58 via repeated division.
  let acc = 0n;
  for (const b of full) acc = (acc << 8n) | BigInt(b);

  let out = '';
  while (acc > 0n) {
    const rem = Number(acc % 58n);
    acc = acc / 58n;
    out = XRPL_ALPHABET[rem] + out;
  }
  // Each leading zero byte encodes as the alphabet's zeroth character.
  for (let i = 0; i < full.length && full[i] === 0; i++) {
    out = XRPL_ALPHABET[0] + out;
  }
  return out;
}

/**
 * Derive the canonical r-address from a 33-byte XRPL public key:
 *   accountID = ripemd160(sha256(pubkey))
 *   address   = base58check( 0x00 || accountID )
 * The FULL 33-byte key (with its 0xED / 0x02 / 0x03 family tag) is hashed —
 * this matches rippled's AccountID derivation for both key types.
 */
function deriveAddress(publicKey33: Uint8Array): string {
  const accountId = ripemd160(sha256(publicKey33));
  const versioned = concatBytes(Uint8Array.of(ACCOUNT_ID_PREFIX), accountId);
  return base58CheckXrpl(versioned);
}

export function verifyXrp(proof: SignedProof): boolean {
  try {
    // Bound every attacker-controlled string before any decode/hash (DoS guard;
    // safe when called outside the dispatcher).
    if (!withinLen(proof.publicKey, MAX_PUBKEY_LEN)) return false;
    if (!withinLen(proof.signature, MAX_SIGNATURE_LEN)) return false;
    if (!withinLen(proof.message, MAX_MESSAGE_LEN)) return false;
    if (!withinLen(proof.address, MAX_ADDRESS_LEN)) return false;

    const publicKey = hexToBytes(proof.publicKey);
    if (publicKey.length !== PUBKEY_LEN) return false;

    const messageBytes = utf8ToBytes(proof.message);
    const sigBytes = decodeSignature(proof.signature);

    // 1. Cryptographic signature check, per scheme.
    let sigOk: boolean;
    if (proof.scheme === 'ed25519-xrpl') {
      // Family tag must be 0xED; verify over the bare 32-byte Edwards key.
      if (publicKey[0] !== ED25519_PREFIX) return false;
      if (sigBytes.length !== ED25519_SIG_LEN) return false;
      const pub32 = publicKey.slice(1);
      sigOk = ed25519.verify(sigBytes, messageBytes, pub32);
    } else if (proof.scheme === 'secp256k1-xrpl') {
      // Compressed point: family tag is 0x02 or 0x03.
      if (publicKey[0] !== 0x02 && publicKey[0] !== 0x03) return false;
      const digest = sha512Half(messageBytes);
      // DER signature over the prehashed digest. lowS:false — rippled does not
      // require low-S of wallet signatures, and malleability is irrelevant for
      // a login proof already bound to a server nonce.
      sigOk = secp256k1.verify(sigBytes, digest, publicKey, {
        prehash: false,
        lowS: false,
        format: 'der',
      });
    } else {
      return false;
    }
    if (!sigOk) return false;

    // 2. Address binding: the key must derive exactly the claimed r-address.
    const derived = deriveAddress(publicKey);
    return derived === proof.address.trim();
  } catch {
    return false;
  }
}
