/**
 * Defense-in-depth input bounds + chain↔scheme binding for the SIWx verify core.
 *
 * Every field of a {@link SignedProof} is attacker-controlled. The cryptographic
 * verifiers already length-check the DECODED material (32-byte keys, 64/65-byte
 * sigs, …), but they hash/decode the raw string FIRST — so an unbounded
 * `message`, `signature`, `publicKey`, or `extra` string lets a malicious client
 * force arbitrarily large allocations and hashing before any check runs (a CPU/
 * memory DoS on the login path). These caps reject oversized inputs up front, so
 * the work any single verify call performs is bounded regardless of input.
 *
 * The bounds are deliberately generous — far above any legitimate value — so
 * they never reject a real wallet, only abuse. They are NOT a security control
 * on their own (the crypto checks are); they cap the blast radius of a hostile
 * caller. One module, used by every verifier and the dispatcher, mirrored by
 * limits.go so TS and Go reject the identical set of inputs.
 */
import type { Chain, SignatureScheme } from './types.js';

/**
 * Max length of the signed CAIP-122 message (UTF-16 code units / bytes). A real
 * login message is a few hundred chars; 8 KiB is ~20× the largest plausible one
 * (long statement + many resource URIs) and still bounds the hash input.
 */
export const MAX_MESSAGE_LEN = 8 * 1024;

/**
 * Max length of an encoded signature string (hex or base64).
 *
 * Most schemes' signatures are tiny (a 64-byte sig is 128 hex / ~88 b64 chars; a
 * BIP-322 witness ~150 chars). The outlier is Cardano CIP-8: the COSE_Sign1
 * envelope EMBEDS the signed payload (the CAIP-122 message itself), so the
 * encoded signature is ≈ 2 × the message bytes (hex) plus COSE overhead. To
 * never reject a legitimate Cardano proof whose message is large-but-legal
 * (up to {@link MAX_MESSAGE_LEN}), this cap must comfortably exceed
 * 2 × MAX_MESSAGE_LEN. 20 KiB does, and is still trivial to bound-check / hash.
 */
export const MAX_SIGNATURE_LEN = 20 * 1024;

/**
 * Max length of an encoded public-key string (hex or base64). Real keys are
 * 32–33 bytes (≤66 hex chars) or a 64-byte Cardano extended key (128 hex); a
 * COSE_Key blob carried in `extra` is bounded separately. 1 KiB is ample.
 */
export const MAX_PUBKEY_LEN = 1024;

/**
 * Max length of an address string. The longest real address is a Cardano base
 * address (~ 'addr1' + 100 chars); 512 covers every chain with wide margin.
 */
export const MAX_ADDRESS_LEN = 512;

/**
 * Max length of any single string field read out of attacker-controlled `extra`
 * (TON domain/payload/addressHashHex, Cardano coseKey hex). A COSE_Key is tens
 * of bytes; an addressHashHex is 64 chars. 8 KiB is far above any real value and
 * bounds the CBOR decode / hashing those fields feed.
 */
export const MAX_EXTRA_STRING_LEN = 8 * 1024;

/**
 * Max number of lines in a CAIP-122 message. Parsing splits on '\n' and loops
 * once per line; with {@link MAX_MESSAGE_LEN} already bounding total size this is
 * a second, cheaper guard so a pathological all-newline payload can't create a
 * huge array. A real message has < 20 lines.
 */
export const MAX_MESSAGE_LINES = 64;

/**
 * Reject a string field that is absent, non-string, or longer than `max`.
 * Returns true when the value is a usable string within bounds. Used at every
 * boundary so the guard logic lives in exactly one place.
 */
export function withinLen(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

/**
 * The set of schemes each chain is allowed to present. The dispatcher verifies
 * on `scheme`, but `chain` is also attacker-controlled, so a proof could pair an
 * arbitrary `chain` with any `scheme` (e.g. chain='evm', scheme='ed25519'). The
 * downstream verifier would reject it anyway (an EVM 0x-address fails base58
 * decode), but relying on a decode failure to catch a category error is fragile.
 * This table rejects every (chain, scheme) mismatch deterministically and up
 * front — closing the cross-chain scheme-confusion class by construction, not by
 * accident. A chain ⇄ scheme pair absent here is `unsupported-scheme`.
 *
 * Mirrored by chainAllowsScheme in limits.go.
 */
const CHAIN_SCHEMES: Record<Chain, ReadonlySet<SignatureScheme>> = {
  evm: new Set(['secp256k1-eip191']),
  solana: new Set(['ed25519']),
  bitcoin: new Set(['bip322']),
  ton: new Set(['ton-proof']),
  xrp: new Set(['secp256k1-xrpl', 'ed25519-xrpl']),
  polkadot: new Set(['sr25519', 'ed25519-substrate', 'ecdsa-substrate']),
  cardano: new Set(['ed25519-cardano']),
};

/** True iff `scheme` is a legitimate signing scheme for `chain`. Fail-closed: an
 * unknown chain (not in the table) returns false. */
export function chainAllowsScheme(chain: Chain, scheme: SignatureScheme): boolean {
  const allowed = CHAIN_SCHEMES[chain];
  return allowed != null && allowed.has(scheme);
}
