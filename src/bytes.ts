/** Byte helpers shared by every verifier. Cross-runtime (Node + browser). */
import { hexToBytes as nobleHexToBytes, bytesToHex, utf8ToBytes, concatBytes } from '@noble/hashes/utils';

export { bytesToHex, utf8ToBytes, concatBytes };

/** Hex → bytes, tolerant of a leading 0x. */
export function hexToBytes(hex: string): Uint8Array {
  return nobleHexToBytes(hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex);
}

/** base64 (standard, with padding) → bytes. */
export function base64ToBytes(b64: string): Uint8Array {
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
