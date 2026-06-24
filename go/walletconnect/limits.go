package walletconnect

// Defense-in-depth input bounds + chain↔scheme binding for the SIWx verify core.
//
// Every field of a Proof is attacker-controlled. The cryptographic verifiers
// already length-check the DECODED material (32-byte keys, 64/65-byte sigs, …),
// but they hash/decode the raw string FIRST — so an unbounded Message,
// Signature, PublicKey, or Extra string lets a malicious client force
// arbitrarily large allocations and hashing before any check runs (a CPU/memory
// DoS on the login path). These caps reject oversized inputs up front, so the
// work any single verify call performs is bounded regardless of input.
//
// The bounds are deliberately generous — far above any legitimate value — so
// they never reject a real wallet, only abuse. They are NOT a security control
// on their own (the crypto checks are); they cap the blast radius of a hostile
// caller. Mirrors src/limits.ts byte-for-byte so TS and Go reject the identical
// set of inputs.

const (
	// maxMessageLen bounds the signed CAIP-122 message (bytes). Mirrors
	// MAX_MESSAGE_LEN.
	maxMessageLen = 8 * 1024
	// maxSignatureLen bounds an encoded signature string. Cardano CIP-8 embeds
	// the signed payload (the message) inside the COSE_Sign1 envelope, so an
	// encoded signature is ≈ 2 × the message bytes; this cap must exceed
	// 2 × maxMessageLen to never reject a legitimate large-message Cardano proof.
	// Mirrors MAX_SIGNATURE_LEN.
	maxSignatureLen = 20 * 1024
	// maxPubKeyLen bounds an encoded public-key string. Mirrors MAX_PUBKEY_LEN.
	maxPubKeyLen = 1024
	// maxAddressLen bounds an address string. Mirrors MAX_ADDRESS_LEN.
	maxAddressLen = 512
	// maxExtraStringLen bounds any single string field read out of Extra.
	// Mirrors MAX_EXTRA_STRING_LEN.
	maxExtraStringLen = 8 * 1024
	// maxMessageLines bounds the line count of a CAIP-122 message. Mirrors
	// MAX_MESSAGE_LINES.
	maxMessageLines = 64
)

// withinLen reports whether s is non-empty and no longer than max. Used at every
// boundary so the guard logic lives in exactly one place. Mirrors the TS
// withinLen (which also rejects empty). Length is measured in bytes, matching
// the TS .length on the ASCII/encoded fields these guard.
func withinLen(s string, max int) bool {
	return len(s) > 0 && len(s) <= max
}

// chainSchemes is the set of schemes each chain is allowed to present. The
// dispatcher verifies on Scheme, but Chain is also attacker-controlled, so a
// proof could pair an arbitrary Chain with any Scheme. The downstream verifier
// would reject a mismatch anyway, but relying on a decode failure to catch a
// category error is fragile. This table rejects every (chain, scheme) mismatch
// deterministically and up front. Mirrors the TS CHAIN_SCHEMES.
var chainSchemes = map[Chain]map[SignatureScheme]bool{
	ChainEVM:      {SchemeSecp256k1EIP191: true},
	ChainSolana:   {SchemeEd25519: true},
	ChainBitcoin:  {SchemeBIP322: true},
	ChainTON:      {SchemeTonProof: true},
	ChainXRP:      {SchemeSecp256k1XRPL: true, SchemeEd25519XRPL: true},
	ChainPolkadot: {SchemeSr25519: true, SchemeEd25519Substr: true, SchemeEcdsaSubstr: true},
	ChainCardano:  {SchemeEd25519Cardano: true},
}

// chainAllowsScheme reports whether scheme is a legitimate signing scheme for
// chain. Fail-closed: an unknown chain returns false. Mirrors the TS
// chainAllowsScheme.
func chainAllowsScheme(chain Chain, scheme SignatureScheme) bool {
	allowed, ok := chainSchemes[chain]
	return ok && allowed[scheme]
}
