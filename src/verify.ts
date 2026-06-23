/**
 * verifyProof — the one server-side entry point. Chain-agnostic: parse the
 * CAIP-122 message, enforce domain/nonce/time, then dispatch to the per-chain
 * cryptographic verifier. Fails closed: any unknown scheme or malformed input
 * returns `{ ok: false, reason }`, never throws.
 *
 * This pure function is mirrored by the Go port in go/walletconnect so IAM
 * verifies identically.
 */
import type { SignedProof, VerifyExpectation, VerifyResult, Chain } from './types.js';
import { parseSiwxMessage } from './caip122.js';
import { verifyEvm } from './evm/verify.js';
import { verifySolana } from './solana/verify.js';

const DEFAULT_SKEW_MS = 5 * 60 * 1000;

function fail(reason: NonNullable<VerifyResult['reason']>): VerifyResult {
  return { ok: false, reason };
}

/** Case-insensitive only for EVM (checksummed hex); all others are exact. */
function addressesEqual(chain: Chain, a: string, b: string): boolean {
  const x = a.trim();
  const y = b.trim();
  return chain === 'evm' ? x.toLowerCase() === y.toLowerCase() : x === y;
}

function parseTime(s: string | undefined): number | null {
  if (s == null) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

/** Cryptographic dispatch. Returns null for not-yet-supported schemes. */
function verifyCrypto(proof: SignedProof): boolean | null {
  switch (proof.scheme) {
    case 'secp256k1-eip191':
      return verifyEvm(proof.message, proof.signature, proof.address);
    case 'ed25519':
      // ed25519-over-message is Solana today; TON uses 'ton-proof'.
      return verifySolana(proof.message, proof.signature, proof.address);
    // Implemented in follow-up modules; fail closed until then.
    case 'bip322':
    case 'ton-proof':
    case 'secp256k1-xrpl':
    case 'ed25519-xrpl':
      return null;
    default:
      return null;
  }
}

export function verifyProof(proof: SignedProof, expected: VerifyExpectation): VerifyResult {
  let parsed;
  try {
    parsed = parseSiwxMessage(proof.message);
  } catch {
    return fail('malformed-message');
  }

  // 1. Binding: the signer in the message must match the proof's address.
  if (!addressesEqual(proof.chain, parsed.address, proof.address)) {
    return fail('address-mismatch');
  }
  if (expected.address != null && !addressesEqual(proof.chain, proof.address, expected.address)) {
    return fail('address-mismatch');
  }

  // 2. Domain + nonce binding (anti-phishing, anti-replay).
  if (parsed.domain !== expected.domain) {
    return fail('domain-mismatch');
  }
  if (parsed.nonce !== expected.nonce) {
    return fail('nonce-mismatch');
  }

  // 3. Time window.
  const now = expected.now ?? Date.now();
  const skew = expected.clockSkewMs ?? DEFAULT_SKEW_MS;
  const exp = parseTime(parsed.expirationTime);
  if (exp != null && now > exp + skew) {
    return fail('expired');
  }
  const nbf = parseTime(parsed.notBefore);
  if (nbf != null && now + skew < nbf) {
    return fail('not-yet-valid');
  }
  const iat = parseTime(parsed.issuedAt);
  if (iat != null && iat - skew > now) {
    return fail('not-yet-valid');
  }

  // 4. Cryptographic signature.
  const crypto = verifyCrypto(proof);
  if (crypto == null) {
    return fail('unsupported-scheme');
  }
  if (!crypto) {
    return fail('bad-signature');
  }

  return { ok: true, address: proof.address, chain: proof.chain };
}
