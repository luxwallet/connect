/**
 * Solana verifier — ed25519 over the raw UTF-8 CAIP-122 message
 * (the bytes a wallet's `signMessage` returns). The account address IS the
 * base58-encoded ed25519 public key, so the key needed to verify is the
 * address itself.
 */
import { ed25519 } from '@noble/curves/ed25519';
import bs58 from 'bs58';
import { utf8ToBytes, decodeSignature } from '../bytes.js';

/** True iff `signature` over `message` was produced by the key behind `address`. */
export function verifySolana(message: string, signature: string, address: string): boolean {
  try {
    const pub = bs58.decode(address.trim());
    if (pub.length !== 32) return false;
    const sig = decodeSignature(signature);
    if (sig.length !== 64) return false;
    return ed25519.verify(sig, utf8ToBytes(message), pub);
  } catch {
    return false;
  }
}
