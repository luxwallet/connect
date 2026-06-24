/**
 * Bitcoin login-signature verifier.
 *
 * Two signing conventions are supported, both verifying a CAIP-122 message
 * against a BTC address (P2PKH '1…', P2WPKH 'bc1q…', P2TR 'bc1p…'):
 *
 *   1. Legacy "Bitcoin Signed Message" — recoverable ECDSA over the
 *      double-SHA256 of the magic-prefixed message. Primary path; works for
 *      every address type (the wallet picks the key form via the header byte).
 *
 *   2. BIP-322 "simple" — a virtual to_spend/to_sign transaction pair whose
 *      witness is verified with BIP-143 (P2WPKH, ECDSA) or BIP-341 (P2TR,
 *      Schnorr) sighash. Used when the signature is a serialized witness stack
 *      rather than a 65-byte recoverable sig.
 *
 * Security posture: fail closed. Every parse/branch returns `false` on the
 * slightest irregularity and the whole function is wrapped so it never throws.
 * The recovered/derived address must match the *type* claimed by the proof and
 * be byte-for-byte equal to `proof.address`.
 */
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';
import type { SignedProof } from '../types.js';
import { base64ToBytes, utf8ToBytes, concatBytes } from '../bytes.js';
import { encodeSegwitAddress } from './bech32.js';
import { base58checkEncode } from './base58check.js';
import { MAX_MESSAGE_LEN, MAX_SIGNATURE_LEN, MAX_ADDRESS_LEN, withinLen } from '../limits.js';

// ── address type ──────────────────────────────────────────────────────────

type BtcAddressType = 'p2pkh' | 'p2wpkh' | 'p2tr';

/** Bitcoin mainnet bech32 human-readable part. */
const HRP = 'bc';

/** Determine the address type from an explicit hint, else from the prefix. */
function addressType(proof: SignedProof): BtcAddressType | null {
  const hint = (proof.extra?.addressType as string | undefined)?.toLowerCase();
  if (hint === 'p2pkh' || hint === 'p2wpkh' || hint === 'p2tr') return hint;

  const a = proof.address;
  if (a.startsWith('bc1p')) return 'p2tr';
  if (a.startsWith('bc1q')) return 'p2wpkh';
  if (a.startsWith('1')) return 'p2pkh';
  return null;
}

// ── hashing helpers ─────────────────────────────────────────────────────────

const sha256d = (b: Uint8Array): Uint8Array => sha256(sha256(b));
const hash160 = (b: Uint8Array): Uint8Array => ripemd160(sha256(b));

/** BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg…). */
function taggedHash(tag: string, ...messages: Uint8Array[]): Uint8Array {
  const tagHash = sha256(utf8ToBytes(tag));
  return sha256(concatBytes(tagHash, tagHash, ...messages));
}

// ── address derivation (pubkey → address string) ────────────────────────────

function deriveP2PKH(pubkey: Uint8Array): string {
  // base58check( 0x00 || hash160(pubkey) )
  return base58checkEncode(0x00, hash160(pubkey));
}

function deriveP2WPKH(pubkeyCompressed: Uint8Array): string | null {
  // bech32(hrp='bc', witver=0, program=hash160(compressed pubkey))
  return encodeSegwitAddress(HRP, 0, hash160(pubkeyCompressed));
}

/** x-only (32-byte) coordinate of a point given as its affine x bigint. */
function xonlyFromBigInt(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * BIP-86 key-path taproot output for an internal pubkey.
 *   t = taggedHash('TapTweak', xonly(P))
 *   Q = lift_x(xonly(P)) + t*G        // internal key is the even-Y lift
 *   program = xonly(Q)
 * Returns the 32-byte tweaked x-only program, or null on any failure.
 */
function taprootTweak(internalXonly: Uint8Array): Uint8Array | null {
  try {
    const Point = secp256k1.Point;
    const n = secp256k1.CURVE.n;
    const x = bytesToBigInt(internalXonly);
    const P = schnorr.utils.lift_x(x); // even-Y point with this x
    const t = bytesToBigInt(taggedHash('TapTweak', internalXonly)) % n;
    if (t === 0n) return null;
    const Q = P.add(Point.BASE.multiply(t));
    const qx = Q.toAffine().x;
    return xonlyFromBigInt(qx);
  } catch {
    return null;
  }
}

function deriveP2TR(internalXonly: Uint8Array): string | null {
  const program = taprootTweak(internalXonly);
  if (program === null) return null;
  return encodeSegwitAddress(HRP, 1, program);
}

function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v;
}

// ── Bitcoin var-int / serialization (CompactSize) ───────────────────────────

function compactSize(n: number): Uint8Array {
  if (n < 0) throw new Error('negative compactSize');
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >>> 8) & 0xff]);
  if (n <= 0xffffffff) {
    return new Uint8Array([0xfe, n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  }
  // 64-bit lengths are never needed for login messages.
  const out = new Uint8Array(9);
  out[0] = 0xff;
  let v = BigInt(n);
  for (let i = 1; i <= 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function u32le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

function u64le(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** length-prefixed (CompactSize) byte string. */
function varBytes(b: Uint8Array): Uint8Array {
  return concatBytes(compactSize(b.length), b);
}

// ════════════════════════════════════════════════════════════════════════════
// 1. LEGACY "Bitcoin Signed Message" (recoverable ECDSA)
// ════════════════════════════════════════════════════════════════════════════

const MSG_MAGIC = utf8ToBytes('\x18Bitcoin Signed Message:\n');

/** digest = sha256d( magic || varint(len) || message ). */
function legacyMessageDigest(message: string): Uint8Array {
  const msg = utf8ToBytes(message);
  return sha256d(concatBytes(MSG_MAGIC, compactSize(msg.length), msg));
}

/**
 * Verify a 65-byte recoverable signature [header || r || s] over the legacy
 * message digest, deriving the address of `type` and comparing to `address`.
 */
function verifyLegacy(
  sig: Uint8Array,
  message: string,
  address: string,
  type: BtcAddressType,
): boolean {
  if (sig.length !== 65) return false;
  const header = sig[0]!;
  // 27-30: uncompressed key; 31-34: compressed key. (BIP-137 also defines
  // 35-42 for segwit, but the recovered key form is what matters here, so we
  // accept the canonical 27-34 range and infer compression from it.)
  if (header < 27 || header > 34) return false;
  const recid = (header - 27) & 3;
  const compressed = header >= 31;

  const r = sig.slice(1, 33);
  const s = sig.slice(33, 65);
  const digest = legacyMessageDigest(message);

  let point;
  try {
    point = secp256k1.Signature.fromCompact(concatBytes(r, s))
      .addRecoveryBit(recid)
      .recoverPublicKey(digest);
  } catch {
    return false;
  }

  // For segwit address types the key MUST be compressed — an uncompressed key
  // cannot back a P2WPKH/P2TR script, so reject rather than silently coercing.
  if ((type === 'p2wpkh' || type === 'p2tr') && !compressed) return false;

  let derived: string | null;
  switch (type) {
    case 'p2pkh': {
      // P2PKH commits to the exact key encoding chosen by the header byte.
      const pub = point.toBytes(compressed);
      derived = deriveP2PKH(pub);
      break;
    }
    case 'p2wpkh': {
      derived = deriveP2WPKH(point.toBytes(true));
      break;
    }
    case 'p2tr': {
      // Internal key = x-only of the recovered (compressed) key.
      const xonly = point.toBytes(true).slice(1);
      derived = deriveP2TR(xonly);
      break;
    }
  }

  return derived !== null && constTimeStrEq(derived, address);
}

/** Length-checked, content-comparing string equality (addresses are public). */
function constTimeStrEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ════════════════════════════════════════════════════════════════════════════
// 2. BIP-322 "simple"
// ════════════════════════════════════════════════════════════════════════════

/** Parse a serialized witness stack: count, then length-prefixed elements. */
function parseWitness(buf: Uint8Array): Uint8Array[] | null {
  let off = 0;
  const readCompact = (): number | null => {
    if (off >= buf.length) return null;
    const first = buf[off++]!;
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      if (off + 2 > buf.length) return null;
      const v = buf[off]! | (buf[off + 1]! << 8);
      off += 2;
      return v;
    }
    if (first === 0xfe) {
      if (off + 4 > buf.length) return null;
      const v = buf[off]! | (buf[off + 1]! << 8) | (buf[off + 2]! << 16) | (buf[off + 3]! * 0x1000000);
      off += 4;
      return v;
    }
    return null; // 64-bit lengths never appear in witness logins
  };

  const count = readCompact();
  if (count === null || count < 1 || count > 4) return null;
  const items: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const len = readCompact();
    if (len === null || len < 0 || off + len > buf.length) return null;
    items.push(buf.slice(off, off + len));
    off += len;
  }
  if (off !== buf.length) return null; // no trailing garbage
  return items;
}

/** scriptPubKey bytes for each supported address type given its program. */
function scriptPubKeyP2WPKH(hash160Pub: Uint8Array): Uint8Array {
  // OP_0 PUSH20 <hash160>
  return concatBytes(new Uint8Array([0x00, 0x14]), hash160Pub);
}
function scriptPubKeyP2TR(programXonly: Uint8Array): Uint8Array {
  // OP_1 PUSH32 <tweaked xonly>
  return concatBytes(new Uint8Array([0x51, 0x20]), programXonly);
}

/**
 * Build the BIP-322 to_spend txid.
 *   to_spend: nVersion=0, vin=[ {prevout=0..00:0xFFFFFFFF,
 *     scriptSig=OP_0 PUSH32 <msgHash>, nSequence=0} ],
 *     vout=[ {value=0, scriptPubKey} ], nLockTime=0
 * txid = sha256d(serialization without witness).
 */
function toSpendTxid(message: string, scriptPubKey: Uint8Array): Uint8Array {
  const msgHash = taggedHash('BIP0322-signed-message', utf8ToBytes(message));
  const scriptSig = concatBytes(new Uint8Array([0x00, 0x20]), msgHash); // OP_0 PUSH32

  const ser = concatBytes(
    u32le(0), // nVersion = 0
    compactSize(1), // vin count
    new Uint8Array(32), // prevout hash = 0
    u32le(0xffffffff), // prevout index = 0xFFFFFFFF
    varBytes(scriptSig),
    u32le(0), // nSequence = 0
    compactSize(1), // vout count
    u64le(0n), // value = 0
    varBytes(scriptPubKey),
    u32le(0), // nLockTime = 0
  );
  return sha256d(ser);
}

/**
 * BIP-143 sighash for the single input of the BIP-322 to_sign tx (P2WPKH).
 * SIGHASH_ALL. scriptCode for P2WPKH = OP_DUP OP_HASH160 PUSH20 <h160>
 * OP_EQUALVERIFY OP_CHECKSIG.
 */
function bip143SighashP2WPKH(toSpendTxid: Uint8Array, hash160Pub: Uint8Array): Uint8Array {
  const outpoint = concatBytes(toSpendTxid, u32le(0)); // to_spend:0
  const nSequence = u32le(0);
  const hashPrevouts = sha256d(outpoint);
  const hashSequence = sha256d(nSequence);

  const scriptCode = concatBytes(
    new Uint8Array([0x19, 0x76, 0xa9, 0x14]), // len(25) OP_DUP OP_HASH160 PUSH20
    hash160Pub,
    new Uint8Array([0x88, 0xac]), // OP_EQUALVERIFY OP_CHECKSIG
  );

  // to_sign single output: value=0, scriptPubKey = OP_RETURN (0x6a).
  const output = concatBytes(u64le(0n), varBytes(new Uint8Array([0x6a])));
  const hashOutputs = sha256d(output);

  const preimage = concatBytes(
    u32le(0), // nVersion = 0
    hashPrevouts,
    hashSequence,
    outpoint,
    scriptCode,
    u64le(0n), // amount of the spent output = 0
    nSequence,
    hashOutputs,
    u32le(0), // nLockTime = 0
    u32le(1), // SIGHASH_ALL
  );
  return sha256d(preimage);
}

/**
 * BIP-341 (taproot key-path) sighash for the single input of the to_sign tx,
 * SIGHASH_DEFAULT (0x00). Single P2TR input, single OP_RETURN output.
 */
function bip341SighashP2TR(toSpendTxid: Uint8Array, scriptPubKey: Uint8Array): Uint8Array {
  const outpoint = concatBytes(toSpendTxid, u32le(0));
  const nSequence = u32le(0);

  const shaPrevouts = sha256(outpoint);
  const shaAmounts = sha256(u64le(0n)); // single spent amount = 0
  const shaScriptPubkeys = sha256(varBytes(scriptPubKey));
  const shaSequences = sha256(nSequence);
  const output = concatBytes(u64le(0n), varBytes(new Uint8Array([0x6a]))); // value=0, OP_RETURN
  const shaOutputs = sha256(output);

  const epoch = new Uint8Array([0x00]);
  const hashType = new Uint8Array([0x00]); // SIGHASH_DEFAULT
  const spendType = new Uint8Array([0x00]); // no annex, key-path
  const inputIndex = u32le(0);

  const sigMsg = concatBytes(
    hashType,
    u32le(0), // nVersion = 0
    u32le(0), // nLockTime = 0
    shaPrevouts,
    shaAmounts,
    shaScriptPubkeys,
    shaSequences,
    shaOutputs,
    spendType,
    inputIndex,
  );
  // BIP-341: tagged hash "TapSighash" over (epoch || sigMsg).
  return taggedHash('TapSighash', concatBytes(epoch, sigMsg));
}

/** Strip a trailing SIGHASH byte from a DER ECDSA signature, returning (der, sighash). */
function splitDerSighash(witnessSig: Uint8Array): { der: Uint8Array; sighash: number } | null {
  if (witnessSig.length < 1) return null;
  const sighash = witnessSig[witnessSig.length - 1]!;
  return { der: witnessSig.slice(0, witnessSig.length - 1), sighash };
}

/** Parse a 64- or 65-byte BIP-340 schnorr sig (optional trailing sighash). */
function splitSchnorrSighash(witnessSig: Uint8Array): { sig: Uint8Array; sighash: number } | null {
  if (witnessSig.length === 64) return { sig: witnessSig, sighash: 0x00 };
  if (witnessSig.length === 65) {
    const sighash = witnessSig[64]!;
    return { sig: witnessSig.slice(0, 64), sighash };
  }
  return null;
}

function verifyBip322P2WPKH(
  witness: Uint8Array[],
  message: string,
  address: string,
): boolean {
  // Witness stack for P2WPKH is exactly [signature, pubkey].
  if (witness.length !== 2) return false;
  const [sigBytes, pubkey] = witness as [Uint8Array, Uint8Array];
  if (pubkey.length !== 33 || (pubkey[0] !== 0x02 && pubkey[0] !== 0x03)) return false;

  // Address binding: the witness pubkey must hash to the claimed P2WPKH address.
  const h160 = hash160(pubkey);
  const derived = deriveP2WPKH(pubkey);
  if (derived === null || !constTimeStrEq(derived, address)) return false;

  const parsed = splitDerSighash(sigBytes);
  if (parsed === null) return false;
  // BIP-322 simple for single-key uses SIGHASH_ALL.
  if (parsed.sighash !== 0x01) return false;

  const txid = toSpendTxid(message, scriptPubKeyP2WPKH(h160));
  const sighash = bip143SighashP2WPKH(txid, h160);

  try {
    const sig = secp256k1.Signature.fromDER(parsed.der);
    // Reject high-S (BIP-146 / consensus-standardness, anti-malleability).
    if (sig.hasHighS()) return false;
    return secp256k1.verify(sig.toCompactRawBytes(), sighash, pubkey, { lowS: true });
  } catch {
    return false;
  }
}

function verifyBip322P2TR(
  witness: Uint8Array[],
  message: string,
  address: string,
): boolean {
  // Key-path spend: witness is exactly [schnorr_sig].
  if (witness.length !== 1) return false;
  const parsed = splitSchnorrSighash(witness[0]!);
  if (parsed === null) return false;
  if (parsed.sighash !== 0x00) return false; // SIGHASH_DEFAULT only

  // Recover the tweaked output key from the claimed address by re-deriving the
  // scriptPubKey from… the address itself: we must decode the program. Since we
  // only have the address string, derive the program by trusting the bech32m
  // body is the output key. We re-encode and compare, then verify schnorr
  // against that x-only output key.
  const program = decodeP2TRProgram(address);
  if (program === null) return false;

  const txid = toSpendTxid(message, scriptPubKeyP2TR(program));
  const sighash = bip341SighashP2TR(txid, scriptPubKeyP2TR(program));

  try {
    return schnorr.verify(parsed.sig, sighash, program);
  } catch {
    return false;
  }
}

/**
 * Decode a bech32m P2TR ('bc1p…') address to its 32-byte witness program.
 * Minimal decoder used only to recover the output key for schnorr verify; it
 * re-validates the checksum by re-encoding and comparing (fail closed).
 */
function decodeP2TRProgram(address: string): Uint8Array | null {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const lower = address.toLowerCase();
  if (lower !== address && address.toUpperCase() !== address) return null; // mixed case
  const pos = lower.lastIndexOf('1');
  if (pos < 1) return null;
  const hrp = lower.slice(0, pos);
  if (hrp !== HRP) return null;
  const dataPart = lower.slice(pos + 1);
  if (dataPart.length < 7) return null; // 1 (witver) + program + 6 checksum

  const values: number[] = [];
  for (const ch of dataPart) {
    const v = CHARSET.indexOf(ch);
    if (v === -1) return null;
    values.push(v);
  }
  const witver = values[0]!;
  if (witver !== 1) return null; // only taproot here

  // Convert 5-bit data (excluding witver and 6-byte checksum) → 8-bit program.
  const data5 = values.slice(1, values.length - 6);
  const program = convert5to8(data5);
  if (program === null || program.length !== 32) return null;

  // Re-encode with bech32m and compare to validate the checksum.
  const reencoded = encodeSegwitAddress(HRP, 1, program);
  if (reencoded === null || reencoded !== lower) return null;
  return program;
}

/** 5-bit groups → 8-bit bytes (frombits=5, tobits=8, pad=false). */
function convert5to8(data: number[]): Uint8Array | null {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const value of data) {
    if (value < 0 || value >> 5 !== 0) return null;
    acc = ((acc << 5) | value) & 0xffffffff;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  // Reject if leftover bits form a non-zero pad (strict, per BIP-173).
  if (bits >= 5) return null;
  if ((acc << (8 - bits)) & 0xff) return null;
  return Uint8Array.from(out);
}

// ════════════════════════════════════════════════════════════════════════════
// dispatch
// ════════════════════════════════════════════════════════════════════════════

export function verifyBitcoin(proof: SignedProof): boolean {
  try {
    // Bound attacker-controlled strings before any decode/hash (DoS guard; safe
    // when called outside the dispatcher).
    if (!withinLen(proof.message, MAX_MESSAGE_LEN)) return false;
    if (!withinLen(proof.signature, MAX_SIGNATURE_LEN)) return false;
    if (!withinLen(proof.address, MAX_ADDRESS_LEN)) return false;

    const type = addressType(proof);
    if (type === null) return false;

    let sig: Uint8Array;
    try {
      sig = base64ToBytes(proof.signature);
    } catch {
      return false;
    }
    if (sig.length === 0) return false;

    // Shape-based dispatch (exactly one path per shape):
    //   • 65 bytes with a valid header → legacy recoverable ECDSA.
    //   • otherwise → BIP-322 simple (serialized witness stack).
    const header = sig[0]!;
    const looksLegacy = sig.length === 65 && header >= 27 && header <= 34;

    if (looksLegacy) {
      return verifyLegacy(sig, proof.message, proof.address, type);
    }

    // BIP-322 simple — only P2WPKH and P2TR are defined for key-path here.
    const witness = parseWitness(sig);
    if (witness === null) return false;
    if (type === 'p2wpkh') return verifyBip322P2WPKH(witness, proof.message, proof.address);
    if (type === 'p2tr') return verifyBip322P2TR(witness, proof.message, proof.address);
    // BIP-322 for P2PKH is not standardized for "simple"; legacy covers it.
    return false;
  } catch {
    // Absolute backstop: never throw out of a verifier.
    return false;
  }
}
