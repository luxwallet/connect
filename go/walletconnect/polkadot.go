package walletconnect

// Polkadot (Substrate) verifier — wallet login-message signatures.
//
// Substrate accounts sign with one of three schemes; the account's key type
// decides which:
//   - sr25519           : Schnorrkel/Ristretto255 (the Polkadot default).
//   - ed25519-substrate : Ed25519 accounts.
//   - ecdsa-substrate   : secp256k1 accounts. The public key is blake2b-256
//     hashed to a 32-byte AccountId before SS58 encoding, and the signature is
//     a 65-byte recoverable ECDSA over blake2b-256(message).
//
// Two independent checks, both of which must hold (decomplected):
//
//  1. Signature: valid over the message a polkadot.js-compatible wallet's
//     signRaw({type:'bytes'}) actually signs — i.e. the CAIP-122 message
//     WRAPPED as "<Bytes>…</Bytes>" (the extension U8A_WRAP_* wrapper).
//       - sr25519           : Schnorrkel verify, signing context "substrate",
//         transcript over the wrapped bytes.
//       - ed25519-substrate : raw EdDSA over the wrapped bytes.
//       - ecdsa-substrate   : recover the secp256k1 key from the 65-byte sig
//         over blake2b-256(wrapped) and require it equals proof.PublicKey.
//  2. Address binding: the claimed SS58 address decodes (valid SS58 checksum)
//     to the AccountId the public key derives — sr25519/ed25519 use the 32-byte
//     public key directly; ecdsa uses blake2b-256(pubkey).
//
// Pure: no I/O, no clock. Fails closed — every error path returns false,
// nothing panics. Mirrors src/polkadot/verify.ts 1:1.
//
// sr25519 is provided by github.com/oasisprotocol/curve25519-voi (BSD-3-Clause,
// permissive — NOT the LGPL ChainSafe/go-schnorrkel). ed25519 is stdlib;
// ecdsa is decred's secp256k1 (ISC), already used by the XRP verifier. SS58
// checksum is blake2b-512 from golang.org/x/crypto (BSD-3). Zero copyleft.
//
// Refs:
//   - https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)
//   - https://github.com/polkadot-js/common (u8aWrapBytes, signatureVerify)
//   - https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md

import (
	"crypto/ed25519"
	"crypto/subtle"

	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/mr-tron/base58"
	"github.com/oasisprotocol/curve25519-voi/primitives/sr25519"
	"golang.org/x/crypto/blake2b"
)

// Substrate public-key lengths by scheme (bytes).
const (
	substrateEdPubLen    = 32 // sr25519, ed25519
	substrateEcdsaPubLen = 33 // compressed secp256k1
	ss58AccountLen       = 32
	ss58ChecksumLen      = 2
	ecdsaRecoverableSig  = 65 // r(32) || s(32) || v(1)
)

// ss58Pre is the SS58 context prefix prepended to the checksum preimage: the
// ASCII bytes of "SS58PRE". Mirrors the TS SS58PRE.
var ss58Pre = []byte{0x53, 0x53, 0x35, 0x38, 0x50, 0x52, 0x45}

// substrateWrapPrefix / substrateWrapPostfix are the polkadot.js extension byte
// wrapper applied by signRaw({type:'bytes'}): "<Bytes>" + data + "</Bytes>".
// Mirrors @polkadot/util's U8A_WRAP_PREFIX / U8A_WRAP_POSTFIX.
var (
	substrateWrapPrefix  = []byte("<Bytes>")
	substrateWrapPostfix = []byte("</Bytes>")
)

// substrateSigningContext is the Schnorrkel signing context Substrate uses
// (matches polkadot.js: signing_context(b"substrate")).
var substrateSigningContext = []byte("substrate")

// wrapBytes reproduces u8aWrapBytes for a CAIP-122 message: it wraps a message
// that is not already wrapped (our messages never are). Mirrors the TS
// u8aWrapBytes used by the verifier.
func wrapBytes(message string) []byte {
	msg := []byte(message)
	out := make([]byte, 0, len(substrateWrapPrefix)+len(msg)+len(substrateWrapPostfix))
	out = append(out, substrateWrapPrefix...)
	out = append(out, msg...)
	out = append(out, substrateWrapPostfix...)
	return out
}

// blake2b256 returns the 32-byte blake2b digest of data.
func blake2b256(data []byte) []byte {
	sum := blake2b.Sum256(data)
	return sum[:]
}

// blake2b512 returns the 64-byte blake2b digest of data.
func blake2b512(data []byte) []byte {
	sum := blake2b.Sum512(data)
	return sum[:]
}

// decodeSS58 decodes an SS58 address to its 32-byte AccountId, validating the
// SS58 checksum. Returns ok=false on any malformation (bad base58, unknown
// prefix length, wrong account length, bad checksum) — fail closed. Supports
// the 1-byte address-type prefixes (network ids 0–63) and the 2-byte form
// (64–16383), each with a 2-byte checksum. Mirrors the TS decodeSs58.
func decodeSS58(address string) ([]byte, bool) {
	raw, err := base58.Decode(trimSpace(address))
	if err != nil {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, false
	}
	var prefixLen int
	if raw[0]&0b0100_0000 == 0 {
		prefixLen = 1
	} else {
		prefixLen = 2
	}
	accountLen := len(raw) - prefixLen - ss58ChecksumLen
	if accountLen != ss58AccountLen {
		return nil, false
	}
	body := raw[:prefixLen+accountLen]
	checksum := raw[prefixLen+accountLen:]

	preimage := make([]byte, 0, len(ss58Pre)+len(body))
	preimage = append(preimage, ss58Pre...)
	preimage = append(preimage, body...)
	full := blake2b512(preimage)
	if subtle.ConstantTimeCompare(full[:ss58ChecksumLen], checksum) != 1 {
		return nil, false
	}
	return raw[prefixLen : prefixLen+accountLen], true
}

// VerifyPolkadot verifies a Polkadot/Substrate login-message signature
// (sr25519 / ed25519 / ecdsa) with SS58 AccountId binding. Both the signature
// check and the address binding must pass. Fails closed on any decode error or
// scheme mismatch — never panics. Port of src/polkadot/verify.ts.
func VerifyPolkadot(proof Proof) bool {
	if len(proof.PublicKey) == 0 {
		return false
	}
	publicKey, err := hexToBytes(proof.PublicKey)
	if err != nil {
		return false
	}

	accountID, ok := decodeSS58(proof.Address)
	if !ok {
		return false
	}

	wrapped := wrapBytes(proof.Message)
	sig, err := decodeSignature(proof.Signature)
	if err != nil {
		return false
	}

	switch proof.Scheme {
	case SchemeSr25519:
		if len(publicKey) != substrateEdPubLen {
			return false
		}
		// Binding: AccountId is the 32-byte public key.
		if subtle.ConstantTimeCompare(accountID, publicKey) != 1 {
			return false
		}
		pk, err := sr25519.NewPublicKeyFromBytes(publicKey)
		if err != nil {
			return false
		}
		s, err := sr25519.NewSignatureFromBytes(sig)
		if err != nil {
			return false
		}
		ctx := sr25519.NewSigningContext(substrateSigningContext)
		return pk.Verify(ctx.NewTranscriptBytes(wrapped), s)

	case SchemeEd25519Substr:
		if len(publicKey) != substrateEdPubLen {
			return false
		}
		if subtle.ConstantTimeCompare(accountID, publicKey) != 1 {
			return false
		}
		if len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(publicKey), wrapped, sig)

	case SchemeEcdsaSubstr:
		if len(publicKey) != substrateEcdsaPubLen {
			return false
		}
		// Binding: AccountId is blake2b-256 of the 33-byte compressed key.
		if subtle.ConstantTimeCompare(accountID, blake2b256(publicKey)) != 1 {
			return false
		}
		// polkadot.js ecdsa signs blake2b-256(message) with a 65-byte
		// recoverable signature (r||s||v). Recover the key and require it
		// equals the declared public key.
		if len(sig) != ecdsaRecoverableSig {
			return false
		}
		digest := blake2b256(wrapped)
		recovered, ok := recoverSecp256k1Compressed(sig, digest)
		if !ok {
			return false
		}
		return subtle.ConstantTimeCompare(recovered, publicKey) == 1

	default:
		return false
	}
}

// recoverSecp256k1Compressed recovers the compressed (33-byte) secp256k1 public
// key from a 65-byte recoverable signature (r||s||v) over digest. The recovery
// id v is the last byte (0/1, or 27/28 — both tolerated). Returns ok=false on
// any failure. Uses decred's ecdsa, which expects the recovery byte FIRST.
func recoverSecp256k1Compressed(sig65, digest []byte) ([]byte, bool) {
	r := sig65[:32]
	s := sig65[32:64]
	v := sig65[64]
	if v >= 27 {
		v -= 27
	}
	if v > 3 {
		return nil, false
	}
	// decred's RecoverCompact wants: [v+27] || r || s.
	compact := make([]byte, 0, 65)
	compact = append(compact, v+27)
	compact = append(compact, r...)
	compact = append(compact, s...)
	pub, _, err := dcrecdsa.RecoverCompact(compact, digest)
	if err != nil {
		return nil, false
	}
	return pub.SerializeCompressed(), true
}

// trimSpace is a tiny local helper to avoid importing strings solely for one
// call site; mirrors strings.TrimSpace for ASCII whitespace.
func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
