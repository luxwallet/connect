package walletconnect

import (
	"crypto/ed25519"
	"strings"

	"github.com/mr-tron/base58"
)

// Solana verifier — ed25519 over the raw UTF-8 CAIP-122 message (the bytes a
// wallet's signMessage returns). The account address IS the base58-encoded
// ed25519 public key, so the key needed to verify is the address itself.
// Mirrors src/solana/verify.ts.

// VerifySolana reports whether signature over message was produced by the key
// behind address (base58 ed25519 public key). Fails closed on any decode error.
func VerifySolana(message, signature, address string) bool {
	// Bound attacker-controlled strings before base58-decoding the address or
	// hashing the message (DoS guard; safe when called outside the dispatcher).
	if len(message) > maxMessageLen || len(signature) == 0 || len(signature) > maxSignatureLen {
		return false
	}
	if len(address) == 0 || len(address) > maxAddressLen {
		return false
	}
	pub, err := base58.Decode(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	if len(pub) != ed25519.PublicKeySize { // 32
		return false
	}
	sig, err := decodeSignature(signature)
	if err != nil {
		return false
	}
	if len(sig) != ed25519.SignatureSize { // 64
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig)
}
