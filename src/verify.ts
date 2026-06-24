/**
 * verifyProof — the one server-side entry point. Chain-agnostic: parse the
 * CAIP-122 message, enforce domain/nonce/time, then dispatch to the per-chain
 * cryptographic verifier. Fails closed: any unknown scheme or malformed input
 * returns `{ ok: false, reason }`, never throws.
 *
 * This pure function is mirrored by the Go port in go/walletconnect so IAM
 * verifies identically.
 *
 * Two entry points, same checks:
 *   - {@link verifyProof}      — synchronous, covers the five @noble-pure
 *     chains (evm/solana/bitcoin/ton/xrp). Pulls no WASM.
 *   - {@link verifyProofAsync} — covers ALL chains including Polkadot, whose
 *     sr25519 verify needs `cryptoWaitReady()`. It delegates the five sync
 *     chains to the same code and awaits the Substrate verifier for the rest.
 */
import type { SignedProof, VerifyExpectation, VerifyResult, Chain } from './types.js';
import { parseSiwxMessage } from './caip122.js';
import { verifyEvm } from './evm/verify.js';
import { verifySolana } from './solana/verify.js';
import { verifyTon } from './ton/verify.js';
import { verifyBitcoin } from './bitcoin/verify.js';
import { verifyXrp } from './xrp/verify.js';

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

/** Synchronous cryptographic dispatch. Returns null for schemes this path does
 * not handle (Substrate, which needs the async verifier). */
function verifyCrypto(proof: SignedProof): boolean | null {
  switch (proof.scheme) {
    case 'secp256k1-eip191':
      return verifyEvm(proof.message, proof.signature, proof.address);
    case 'ed25519':
      // ed25519-over-message is Solana today; TON uses 'ton-proof'.
      return verifySolana(proof.message, proof.signature, proof.address);
    case 'ton-proof':
      return verifyTon(proof);
    case 'bip322':
      return verifyBitcoin(proof);
    case 'secp256k1-xrpl':
    case 'ed25519-xrpl':
      return verifyXrp(proof);
    default:
      return null;
  }
}

/**
 * Run every check up to (but excluding) the cryptographic one. Returns the
 * failing {@link VerifyResult} when a binding/time check fails, or `null` when
 * all of them pass (so the caller proceeds to crypto). Shared by both the sync
 * and async entry points so the order and reasons are identical.
 */
function preCrypto(proof: SignedProof, expected: VerifyExpectation): VerifyResult | null {
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

  return null;
}

/** Map a crypto result (`true`/`false`) to the final {@link VerifyResult}. */
function finish(proof: SignedProof, ok: boolean): VerifyResult {
  if (!ok) return fail('bad-signature');
  return { ok: true, address: proof.address, chain: proof.chain };
}

/**
 * Verify a {@link SignedProof} synchronously. Handles the five @noble-pure
 * chains (evm/solana/bitcoin/ton/xrp). For Polkadot (Substrate sr25519/ed25519/
 * ecdsa) use {@link verifyProofAsync} — a Substrate proof here returns
 * `unsupported-scheme`.
 */
export function verifyProof(proof: SignedProof, expected: VerifyExpectation): VerifyResult {
  const pre = preCrypto(proof, expected);
  if (pre != null) return pre;

  const crypto = verifyCrypto(proof);
  if (crypto == null) {
    return fail('unsupported-scheme');
  }
  return finish(proof, crypto);
}

/**
 * Verify a {@link SignedProof} for ANY supported chain, including Polkadot.
 * Identical binding/time checks and reasons as {@link verifyProof}; only the
 * cryptographic step is async (Substrate sr25519 needs `cryptoWaitReady()`).
 * The five sync chains are delegated to the same code — no behavioural drift.
 */
export async function verifyProofAsync(
  proof: SignedProof,
  expected: VerifyExpectation,
): Promise<VerifyResult> {
  const pre = preCrypto(proof, expected);
  if (pre != null) return pre;

  switch (proof.scheme) {
    case 'sr25519':
    case 'ed25519-substrate':
    case 'ecdsa-substrate': {
      const { verifyPolkadot } = await import('./polkadot/verify.js');
      return finish(proof, await verifyPolkadot(proof));
    }
    default: {
      const crypto = verifyCrypto(proof);
      if (crypto == null) return fail('unsupported-scheme');
      return finish(proof, crypto);
    }
  }
}
