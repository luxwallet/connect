package walletconnect

// Cardano verifier — CIP-8 / CIP-30 signData (COSE_Sign1 + COSE_Key, ed25519).
//
// Port of src/cardano/verify.ts, byte-for-byte. A CIP-30 wallet's
// api.signData(addrHex, payloadHex) returns { signature: cbor<COSE_Sign1>,
// key: cbor<COSE_Key> }; the connector packs them into a Proof:
//
//	Scheme    "ed25519-cardano"
//	Address   bech32 address (addr1…/stake1…)
//	PublicKey COSE_Key ed25519 public key (hex; 32B raw or 64B extended)
//	Signature COSE_Sign1 cbor (hex)
//	Message   CAIP-122 string (== the COSE_Sign1 payload, non-hashed)
//	Extra["coseKey"] COSE_Key cbor (hex) [optional; PublicKey is authoritative]
//
// Two independent checks, both must hold (decomplected, like Polkadot):
//
//  1. Signature: ed25519 over the COSE Sig_structure
//     [ "Signature1", protected, external_aad(empty), payload ] reconstructed
//     from the COSE_Sign1 CBOR. The embedded payload MUST equal the proof's
//     CAIP-122 message bytes (non-hashed signing).
//  2. Address binding: blake2b-224(pubkey[:32]) == the 28-byte key credential
//     embedded in the bech32 address (payment credential for addr1…, stake
//     credential for stake1…). The bech32 checksum must be valid.
//
// Pure: no I/O, no clock. Fails closed — every error path returns false,
// nothing panics. ed25519 is stdlib; blake2b is golang.org/x/crypto (BSD-3);
// CBOR/bech32 are inline. Zero copyleft.
//
// Refs:
//   - CIP-8  https://cips.cardano.org/cip/CIP-0008
//   - CIP-30 https://cips.cardano.org/cip/CIP-0030
//   - CIP-19 https://cips.cardano.org/cip/CIP-0019
//   - RFC 9052 https://datatracker.ietf.org/doc/rfc9052/

import (
	"crypto/ed25519"
	"crypto/subtle"

	"golang.org/x/crypto/blake2b"
)

const (
	cardanoPubKeyLen  = 32 // ed25519 public key
	cardanoSigLen     = 64 // ed25519 signature
	cardanoKeyHashLen = 28 // blake2b-224 key credential
	coseKeyXLabel     = -2 // COSE_Key map key for the public key (x), RFC 9052
)

// blake2b224 returns the 28-byte blake2b digest of data — the Cardano
// key-credential function.
func blake2b224(data []byte) []byte {
	h, _ := blake2b.New(cardanoKeyHashLen, nil) // err only on bad size/key; 28/nil is valid
	h.Write(data)
	return h.Sum(nil)
}

// cardanoKeyCredential extracts the 28-byte key credential that must equal
// blake2b-224(pubkey) from a decoded Cardano address. Returns ok=false for
// address types this login flow does not bind (script credentials, pointer,
// Byron, malformed). Mirrors the TS keyCredentialFromAddress.
func cardanoKeyCredential(hrp string, data []byte) ([]byte, bool) {
	if len(data) < 1+cardanoKeyHashLen {
		return nil, false
	}
	header := data[0]
	typ := header >> 4

	switch hrp {
	case "addr", "addr_test":
		switch typ {
		// Base: payment=KEY binds an ed25519 key, i.e. type 0 or 2.
		case 0, 2:
			if len(data) < 1+2*cardanoKeyHashLen {
				return nil, false
			}
			return data[1 : 1+cardanoKeyHashLen], true
		// Enterprise key: type 6.
		case 6:
			if len(data) != 1+cardanoKeyHashLen {
				return nil, false
			}
			return data[1 : 1+cardanoKeyHashLen], true
		default:
			return nil, false
		}
	case "stake", "stake_test":
		// type 14 = stake key-hash; 15 = script-hash.
		if typ == 14 {
			if len(data) != 1+cardanoKeyHashLen {
				return nil, false
			}
			return data[1 : 1+cardanoKeyHashLen], true
		}
		return nil, false
	default:
		return nil, false
	}
}

// cardanoPublicKeyFromCoseKey reads the ed25519 public key (COSE_Key map key
// -2) from a hex COSE_Key. Returns ok=false if absent or not bytes.
func cardanoPublicKeyFromCoseKey(coseKeyHex string) ([]byte, bool) {
	raw, err := hexToBytes(coseKeyHex)
	if err != nil {
		return nil, false
	}
	decoded, ok := cborDecode(raw)
	if !ok {
		return nil, false
	}
	m, ok := decoded.(*cborMap)
	if !ok {
		return nil, false
	}
	x, ok := m.getInt(coseKeyXLabel)
	if !ok {
		return nil, false
	}
	b, ok := x.([]byte)
	if !ok {
		return nil, false
	}
	return b, true
}

// cardanoCoseSign1 narrows a CBOR value to a definite COSE_Sign1 quad.
type cardanoCoseSign1 struct {
	protectedSer []byte
	unprotected  *cborMap
	payload      []byte // nil means CBOR null
	hasPayload   bool
	signature    []byte
}

func cardanoAsCoseSign1(v cborValue, ok bool) (cardanoCoseSign1, bool) {
	var out cardanoCoseSign1
	if !ok {
		return out, false
	}
	arr, isArr := v.([]cborValue)
	if !isArr || len(arr) != 4 {
		return out, false
	}
	p, okP := arr[0].([]byte)
	if !okP {
		return out, false
	}
	u, okU := arr[1].(*cborMap)
	if !okU {
		return out, false
	}
	sig, okS := arr[3].([]byte)
	if !okS {
		return out, false
	}
	out.protectedSer = p
	out.unprotected = u
	out.signature = sig
	switch pay := arr[2].(type) {
	case []byte:
		out.payload = pay
		out.hasPayload = true
	case nil:
		out.payload = nil
		out.hasPayload = false
	default:
		return out, false
	}
	return out, true
}

// VerifyCardano verifies a Cardano CIP-8/CIP-30 login proof (ed25519 over
// COSE_Sign1) with blake2b-224 address binding. Both the signature check and the
// address binding must pass. Fails closed on any decode error, length mismatch,
// hashed payload, or scheme mismatch — never panics. Port of
// src/cardano/verify.ts verifyCardano.
func VerifyCardano(proof Proof) bool {
	// Scheme + bounded presence of every attacker-controlled string. Bounds cap
	// the COSE/CBOR decode + hashing and make this exported verifier safe when
	// called directly (the dispatcher also gates).
	if proof.Scheme != SchemeEd25519Cardano {
		return false
	}
	if !withinLen(proof.PublicKey, maxPubKeyLen) || !withinLen(proof.Signature, maxSignatureLen) ||
		!withinLen(proof.Message, maxMessageLen) || !withinLen(proof.Address, maxAddressLen) {
		return false
	}

	fullPub, err := hexToBytes(proof.PublicKey)
	if err != nil {
		return false
	}
	if len(fullPub) != cardanoPubKeyLen && len(fullPub) != 2*cardanoPubKeyLen {
		return false
	}
	pub := fullPub[:cardanoPubKeyLen]

	// Defence in depth: when a COSE_Key is carried, its -2 must equal PublicKey.
	if proof.Extra != nil {
		if ck, isStr := proof.Extra["coseKey"].(string); isStr && len(ck) > 0 {
			if len(ck) > maxExtraStringLen {
				return false
			}
			fromKey, ok := cardanoPublicKeyFromCoseKey(ck)
			if !ok {
				return false
			}
			if len(fromKey) < cardanoPubKeyLen {
				return false
			}
			if subtle.ConstantTimeCompare(fromKey[:cardanoPubKeyLen], pub) != 1 {
				return false
			}
		}
	}

	// --- 1. Address binding: blake2b-224(pubkey) == key credential. ---
	hrp, addrData, ok := cardanoBech32Decode(trimSpace(proof.Address))
	if !ok {
		return false
	}
	credential, ok := cardanoKeyCredential(hrp, addrData)
	if !ok {
		return false
	}
	if subtle.ConstantTimeCompare(blake2b224(pub), credential) != 1 {
		return false
	}

	// --- 2. Signature over the reconstructed COSE Sig_structure. ---
	sigBytes, err := hexToBytes(proof.Signature)
	if err != nil {
		return false
	}
	cose, ok := cardanoAsCoseSign1(cborDecode(sigBytes))
	if !ok {
		return false
	}

	// Reject hashed payloads: our login flow signs the message verbatim.
	if hashed, has := cose.unprotected.getStr("hashed"); has {
		if b, isBool := hashed.(bool); isBool && b {
			return false
		}
	}

	// Bind the signed payload to the CAIP-122 message.
	if !cose.hasPayload {
		return false
	}
	if subtle.ConstantTimeCompare(cose.payload, []byte(proof.Message)) != 1 {
		return false
	}

	if len(cose.signature) != cardanoSigLen {
		return false
	}

	sigStruct := cborBuildSigStructure(cose.protectedSer, []byte{}, cose.payload)
	return ed25519.Verify(ed25519.PublicKey(pub), sigStruct, cose.signature)
}
