package walletconnect

// XRP (XRP Ledger) verifier — wallet login-message signatures.
//
// XRPL accounts use either a secp256k1 or an ed25519 keypair. The connector
// carries the public key in proof.PublicKey (33 bytes in XRPL's canonical
// form). This verifier does two independent checks, both of which must hold:
//
//  1. Signature: the signature is valid over the CAIP-122 message under the
//     declared key, using XRPL's signing convention for the scheme.
//     - ed25519-xrpl   : raw EdDSA over the UTF-8 message bytes.
//     - secp256k1-xrpl : ECDSA over the "sha512half" digest (first 32 bytes
//       of SHA-512 of the message), DER-encoded.
//  2. Address binding: the public key derives the claimed r-address via the
//     standard XRPL AccountID derivation (RIPEMD160(SHA256(pubkey)) under the
//     0x00 account prefix, base58check with the XRPL alphabet).
//
// Decomplected: signature verification and address binding are separate, each
// complete on its own. Fails closed — every error path returns false, nothing
// panics. Pure: no I/O, no clock. Mirrors src/xrp/verify.ts 1:1.
//
// Refs:
//   - https://xrpl.org/cryptographic-keys.html (key prefixes, AccountID)
//   - https://xrpl.org/base58-encodings.html (XRPL base58 alphabet, type prefix)
//   - https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // XRPL AccountID is defined in terms of RIPEMD-160.
)

// xrplAlphabet is XRPL's base58 alphabet (NOT the Bitcoin/IPFS alphabet — a
// different order). Mirrors the TS XRPL_ALPHABET.
const xrplAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// xrpAccountIDPrefix is the account address type prefix byte (the leading 'r'
// once base58-encoded). Mirrors the TS ACCOUNT_ID_PREFIX.
const xrpAccountIDPrefix = 0x00

// XRPL public keys are always 33 bytes: a 1-byte family tag + 32-byte key.
const (
	xrpPubKeyLen     = 33
	xrpEd25519Prefix = 0xed
	xrpEd25519SigLen = 64
)

// xrpBig58 is the base-58 radix as a big.Int, allocated once.
var xrpBig58 = big.NewInt(58)

// xrpSha512Half is XRPL's "sha512half": the first half (32 bytes) of SHA-512
// over the input. Mirrors the TS sha512Half.
func xrpSha512Half(data []byte) []byte {
	sum := sha512.Sum512(data)
	return sum[:32]
}

// xrpSha256 is a one-line SHA-256 returning a slice (the digest is consumed by
// further hashing / concatenation, never compared as an array).
func xrpSha256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// xrpBase58Check encodes a version-prefixed payload using the XRPL alphabet. A
// 4-byte double-SHA256 checksum is appended before encoding. Pure big-integer
// base conversion so it matches the TS base58CheckXrpl byte-for-byte, including
// the leading-zero-byte handling. Mirrors the TS base58CheckXrpl.
func xrpBase58Check(payload []byte) string {
	checksum := xrpSha256(xrpSha256(payload))[:4]
	full := make([]byte, 0, len(payload)+4)
	full = append(full, payload...)
	full = append(full, checksum...)

	// Big-endian base-256 -> base-58 via repeated division.
	acc := new(big.Int).SetBytes(full)
	mod := new(big.Int)
	var sb []byte // built reversed, flipped at the end
	for acc.Sign() > 0 {
		acc.DivMod(acc, xrpBig58, mod)
		sb = append(sb, xrplAlphabet[mod.Int64()])
	}
	// Each leading zero byte encodes as the alphabet's zeroth character.
	for i := 0; i < len(full) && full[i] == 0; i++ {
		sb = append(sb, xrplAlphabet[0])
	}
	// Reverse: digits were produced least-significant-first, and the leading
	// zeros must end up at the front.
	for i, j := 0, len(sb)-1; i < j; i, j = i+1, j-1 {
		sb[i], sb[j] = sb[j], sb[i]
	}
	return string(sb)
}

// xrpDeriveAddress derives the canonical r-address from a 33-byte XRPL public
// key:
//
//	accountID = ripemd160(sha256(pubkey))
//	address   = base58check( 0x00 || accountID )
//
// The FULL 33-byte key (with its 0xED / 0x02 / 0x03 family tag) is hashed —
// this matches rippled's AccountID derivation for both key types. Mirrors the
// TS deriveAddress.
func xrpDeriveAddress(publicKey33 []byte) string {
	rip := ripemd160.New()
	rip.Write(xrpSha256(publicKey33))
	accountID := rip.Sum(nil)

	versioned := make([]byte, 0, 1+len(accountID))
	versioned = append(versioned, xrpAccountIDPrefix)
	versioned = append(versioned, accountID...)
	return xrpBase58Check(versioned)
}

// VerifyXrp verifies an XRP Ledger login-message signature (secp256k1 /
// ed25519) with AccountID r-address binding. Both the signature check and the
// address binding must pass. Fails closed on any decode error or scheme
// mismatch — never panics. Port of src/xrp/verify.ts.
func VerifyXrp(proof Proof) bool {
	if len(proof.PublicKey) == 0 {
		return false
	}

	publicKey, err := hexToBytes(proof.PublicKey)
	if err != nil {
		return false
	}
	if len(publicKey) != xrpPubKeyLen {
		return false
	}

	messageBytes := []byte(proof.Message)
	sigBytes, err := decodeSignature(proof.Signature)
	if err != nil {
		return false
	}

	// 1. Cryptographic signature check, per scheme.
	var sigOK bool
	switch proof.Scheme {
	case SchemeEd25519XRPL:
		// Family tag must be 0xED; verify over the bare 32-byte Edwards key.
		if publicKey[0] != xrpEd25519Prefix {
			return false
		}
		if len(sigBytes) != xrpEd25519SigLen {
			return false
		}
		pub32 := publicKey[1:]
		sigOK = ed25519.Verify(ed25519.PublicKey(pub32), messageBytes, sigBytes)

	case SchemeSecp256k1XRPL:
		// Compressed point: family tag is 0x02 or 0x03.
		if publicKey[0] != 0x02 && publicKey[0] != 0x03 {
			return false
		}
		pubKey, err := secp256k1.ParsePubKey(publicKey)
		if err != nil {
			return false
		}
		// DER signature over the prehashed sha512half digest. ParseDERSignature
		// enforces canonical DER and 1 <= s <= n-1; Verify does NOT require
		// low-S — matching the TS { lowS: false }. Malleability is irrelevant
		// for a login proof already bound to a server nonce.
		sig, err := ecdsa.ParseDERSignature(sigBytes)
		if err != nil {
			return false
		}
		digest := xrpSha512Half(messageBytes)
		sigOK = sig.Verify(digest, pubKey)

	default:
		return false
	}
	if !sigOK {
		return false
	}

	// 2. Address binding: the key must derive exactly the claimed r-address.
	derived := xrpDeriveAddress(publicKey)
	return derived == strings.TrimSpace(proof.Address)
}
