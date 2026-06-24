package walletconnect

import (
	"strings"
	"time"
)

// SignatureScheme is the signing scheme that produced a proof. The verifier
// dispatches on this, not on Chain. Mirrors the TS SignatureScheme union.
type SignatureScheme string

const (
	SchemeSecp256k1EIP191 SignatureScheme = "secp256k1-eip191"  // EVM personal_sign (EIP-191)
	SchemeEd25519         SignatureScheme = "ed25519"           // Solana, TON
	SchemeBIP322          SignatureScheme = "bip322"            // Bitcoin message signing (BIP-322)
	SchemeTonProof        SignatureScheme = "ton-proof"         // TON Connect ton_proof (ed25519 inside)
	SchemeSecp256k1XRPL   SignatureScheme = "secp256k1-xrpl"    // XRPL signMessage (secp256k1)
	SchemeEd25519XRPL     SignatureScheme = "ed25519-xrpl"      // XRPL ed25519 keypair
	SchemeSr25519         SignatureScheme = "sr25519"           // Polkadot/Substrate default (Schnorrkel/Ristretto255)
	SchemeEd25519Substr   SignatureScheme = "ed25519-substrate" // Polkadot/Substrate ed25519 accounts
	SchemeEcdsaSubstr     SignatureScheme = "ecdsa-substrate"   // Polkadot/Substrate ecdsa (secp256k1) accounts
)

// Proof is what a wallet hands back after signing — everything the server needs
// to verify. Mirrors the TS SignedProof.
type Proof struct {
	Chain     Chain
	Scheme    SignatureScheme
	Address   string
	PublicKey string
	Message   string
	Signature string
	Extra     map[string]any
}

// Expectation holds the server-side expectations checked against the parsed
// message during verify. Mirrors the TS VerifyExpectation, but expressed with
// Go-native time types: Now overrides "now" (zero value => time.Now()) and
// ClockSkew is the tolerated skew (zero value => DefaultClockSkew).
type Expectation struct {
	Domain    string
	Nonce     string
	Address   string // optional; require an exact address (case-insensitive for EVM)
	Now       time.Time
	ClockSkew time.Duration
}

// DefaultClockSkew matches the TS DEFAULT_SKEW_MS (5 minutes).
const DefaultClockSkew = 5 * time.Minute

// Reason is a machine-readable failure reason. The string values match the TS
// VerifyResult.reason union exactly.
type Reason string

const (
	ReasonBadSignature      Reason = "bad-signature"
	ReasonAddressMismatch   Reason = "address-mismatch"
	ReasonDomainMismatch    Reason = "domain-mismatch"
	ReasonNonceMismatch     Reason = "nonce-mismatch"
	ReasonExpired           Reason = "expired"
	ReasonNotYetValid       Reason = "not-yet-valid"
	ReasonMalformedMessage  Reason = "malformed-message"
	ReasonUnsupportedScheme Reason = "unsupported-scheme"
	ReasonMissingPublicKey  Reason = "missing-public-key"
)

// Result mirrors the TS VerifyResult. Reason is empty when OK is true.
type Result struct {
	OK      bool
	Reason  Reason
	Address string
	Chain   Chain
}

func fail(r Reason) Result { return Result{OK: false, Reason: r} }

// addressesEqual is case-insensitive only for EVM (checksummed hex); all other
// chains compare exactly. Mirrors the TS addressesEqual.
func addressesEqual(chain Chain, a, b string) bool {
	x := strings.TrimSpace(a)
	y := strings.TrimSpace(b)
	if chain == ChainEVM {
		return strings.EqualFold(x, y)
	}
	return x == y
}

// parseTime parses an ISO-8601 timestamp the way JS Date.parse does for the
// values newChallenge emits (RFC3339 with milliseconds and a 'Z' zone). It
// tolerates the RFC3339 variants Date.parse accepts. ok=false means the field
// was absent or unparseable — both treated as "no constraint", matching the TS
// `parseTime` returning null.
func parseTime(s *string) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, *s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// crypto dispatches to the per-chain cryptographic verifier. The (ok, supported)
// pair mirrors the TS `boolean | null`: supported=false maps to TS null
// (unsupported scheme); supported=true with ok=false maps to TS false.
func crypto(p Proof) (ok, supported bool) {
	switch p.Scheme {
	case SchemeSecp256k1EIP191:
		return VerifyEVM(p.Message, p.Signature, p.Address), true
	case SchemeEd25519:
		// ed25519-over-message is Solana today; TON uses 'ton-proof'.
		return VerifySolana(p.Message, p.Signature, p.Address), true
	case SchemeTonProof:
		return VerifyTon(p), true
	case SchemeBIP322:
		return VerifyBitcoin(p), true
	case SchemeSecp256k1XRPL, SchemeEd25519XRPL:
		return VerifyXrp(p), true
	case SchemeSr25519, SchemeEd25519Substr, SchemeEcdsaSubstr:
		return VerifyPolkadot(p), true
	default:
		return false, false
	}
}

// VerifyProof is the one server-side entry point. Chain-agnostic: parse the
// CAIP-122 message, enforce address/domain/nonce/time, then dispatch to the
// per-chain cryptographic verifier. Fails closed: any unknown scheme or
// malformed input returns {OK: false, Reason}, never panics. Mirrors the TS
// verifyProof exactly, including check order and reasons.
func VerifyProof(proof Proof, expected Expectation) Result {
	parsed, err := ParseSiwxMessage(proof.Message)
	if err != nil {
		return fail(ReasonMalformedMessage)
	}

	// 1. Binding: the signer in the message must match the proof's address.
	if !addressesEqual(proof.Chain, parsed.Address, proof.Address) {
		return fail(ReasonAddressMismatch)
	}
	if expected.Address != "" && !addressesEqual(proof.Chain, proof.Address, expected.Address) {
		return fail(ReasonAddressMismatch)
	}

	// 2. Domain + nonce binding (anti-phishing, anti-replay).
	if parsed.Domain != expected.Domain {
		return fail(ReasonDomainMismatch)
	}
	if parsed.Nonce != expected.Nonce {
		return fail(ReasonNonceMismatch)
	}

	// 3. Time window.
	now := expected.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := expected.ClockSkew
	if skew == 0 {
		skew = DefaultClockSkew
	}
	if exp, ok := parseTime(parsed.ExpirationTime); ok {
		// now > exp + skew
		if now.After(exp.Add(skew)) {
			return fail(ReasonExpired)
		}
	}
	if nbf, ok := parseTime(parsed.NotBefore); ok {
		// now + skew < nbf
		if now.Add(skew).Before(nbf) {
			return fail(ReasonNotYetValid)
		}
	}
	if iat, ok := parseTime(&parsed.IssuedAt); ok {
		// iat - skew > now
		if iat.Add(-skew).After(now) {
			return fail(ReasonNotYetValid)
		}
	}

	// 4. Cryptographic signature.
	ok, supported := crypto(proof)
	if !supported {
		return fail(ReasonUnsupportedScheme)
	}
	if !ok {
		return fail(ReasonBadSignature)
	}

	return Result{OK: true, Address: proof.Address, Chain: proof.Chain}
}
