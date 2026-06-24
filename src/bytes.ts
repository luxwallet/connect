/** Byte helpers shared by every verifier. Cross-runtime (Node + browser). */
import { hexToBytes as nobleHexToBytes, bytesToHex, utf8ToBytes, concatBytes } from '@noble/hashes/utils';

export { bytesToHex, utf8ToBytes, concatBytes };

/** Hex → bytes, tolerant of a leading 0x. Throws on a non-string or non-hex
 * input (odd length, out-of-alphabet) — the noble decoder is strict, and every
 * caller wraps the decode so the throw becomes a fail-closed `false`. */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw new TypeError('hexToBytes: not a string');
  return nobleHexToBytes(hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex);
}

/** Strict standard base64 (with padding) → bytes. Unlike `atob` / Node's
 * `Buffer.from(…, 'base64')` — both of which silently drop characters outside
 * the alphabet — this rejects any non-base64 input so a malformed signature
 * cannot be coerced into a shorter byte string. Throws on a non-string or a
 * string that is not canonical base64; callers wrap the decode and fail closed. */
export function base64ToBytes(b64: string): Uint8Array {
  if (typeof b64 !== 'string') throw new TypeError('base64ToBytes: not a string');
  // Canonical base64: groups of 4 of [A-Za-z0-9+/], optional trailing '=' pad.
  // Reject whitespace/newlines and the URL-safe alphabet (-, _) — those are not
  // what wallets emit, and accepting them would widen the parse surface.
  if (b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
    throw new Error('base64ToBytes: invalid base64');
  }
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Node
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === 'function') {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
    return btoa(bin);
  }
  return Buffer.from(bytes).toString('base64');
}

/** Decode a signature that may be hex (0x…) or base64 into raw bytes. */
export function decodeSignature(sig: string): Uint8Array {
  const s = sig.trim();
  if (s.startsWith('0x') || s.startsWith('0X')) return hexToBytes(s);
  // Heuristic: pure hex (even length, [0-9a-f]) → hex, else base64.
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return hexToBytes(s);
  return base64ToBytes(s);
}
