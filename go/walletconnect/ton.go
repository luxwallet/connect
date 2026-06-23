package walletconnect

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"math"
)

// TON verifier — TON Connect `ton_proof` (ed25519).
//
// Port of src/ton/verify.ts, byte-for-byte. Unlike text-signing chains, TON
// signs a structured `ton_proof` envelope, not the CAIP-122 string. The
// connector carries the envelope in proof.Extra and the wallet public key in
// proof.PublicKey; this verifier reconstructs the ton_proof signing message
// exactly as the TON Connect spec defines it, checks the ed25519 signature over
// the double-SHA-256 digest, and binds the envelope to the CAIP-122 login
// message (nonce == payload, address == signer).
//
//	message = "ton-proof-item-v2/"
//	        ‖ int32BE(workchain)
//	        ‖ addressHash(32)
//	        ‖ uint32LE(len(domain))
//	        ‖ domain
//	        ‖ uint64LE(timestamp)
//	        ‖ payload
//	signed  = sha256( 0xffff ‖ "ton-connect" ‖ sha256(message) )
//	ok      = ed25519.Verify(publicKey, signed, signature)
//
// Pure: no I/O, no network, no clock. Fails closed — any malformed or missing
// field returns false; never panics.

// ton_proof static prefixes (TON Connect v2). Distinct package-level names so
// they never collide with the parallel XRP/Bitcoin ports in this flat package.
var (
	tonProofPrefix   = []byte("ton-proof-item-v2/")
	tonConnectPrefix = []byte("ton-connect")
)

// ed25519 public keys are 32 bytes; signatures are 64 bytes; addr hash is 32.
const (
	tonPubKeyLen   = 32
	tonSigLen      = 64
	tonAddrHashLen = 32
)

// tonProofExtra is the `extra` envelope a TON connector attaches to a ton_proof.
// Mirrors the TS TonProofExtra interface.
type tonProofExtra struct {
	timestamp      int64
	domain         string
	payload        string
	workchain      int32
	addressHashHex string
}

// tonExtraInt narrows a JSON-decoded numeric field to an integer. proof.Extra is
// map[string]any, so numbers arrive as float64 after JSON decoding. This rejects
// absent values, non-numbers, NaN/Inf, and non-integral floats — the Go analog
// of the TS `typeof === 'number' && Number.isInteger(...)` guard. Returns the
// integral value as int64 and ok=true only when the float is an exact integer
// representable without loss.
func tonExtraInt(v any) (int64, bool) {
	f, isFloat := v.(float64)
	if !isFloat {
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	if math.Trunc(f) != f {
		return 0, false
	}
	// Guard the float64 -> int64 conversion: |f| must be within int64 range and
	// exactly representable (no precision loss past 2^53). math.MaxInt64 is not
	// exactly representable as a float64, so compare against the float bound.
	if f < math.MinInt64 || f >= 9223372036854775808.0 { // 2^63
		return 0, false
	}
	return int64(f), true
}

// tonReadExtra narrows proof.Extra to the ton_proof envelope, validating field
// shapes. Mirrors the TS readExtra: timestamp is a finite non-negative integer
// (unix seconds); workchain is a finite integer (0 = basechain, -1 =
// masterchain); domain/payload/addressHashHex are strings. Returns ok=false on
// any shape violation, fail-closed.
func tonReadExtra(extra map[string]any) (tonProofExtra, bool) {
	var out tonProofExtra
	if extra == nil {
		return out, false
	}

	// timestamp: finite, non-negative integer number of unix seconds.
	ts, ok := tonExtraInt(extra["timestamp"])
	if !ok || ts < 0 {
		return out, false
	}

	// workchain: finite integer; must fit in a signed 32-bit field (int32BE).
	wc, ok := tonExtraInt(extra["workchain"])
	if !ok || wc < math.MinInt32 || wc > math.MaxInt32 {
		return out, false
	}

	domain, ok := extra["domain"].(string)
	if !ok {
		return out, false
	}
	payload, ok := extra["payload"].(string)
	if !ok {
		return out, false
	}
	addressHashHex, ok := extra["addressHashHex"].(string)
	if !ok {
		return out, false
	}

	out = tonProofExtra{
		timestamp:      ts,
		domain:         domain,
		payload:        payload,
		workchain:      int32(wc),
		addressHashHex: addressHashHex,
	}
	return out, true
}

// tonBuildMessage reconstructs the ton_proof message body that the wallet
// hashed. Mirrors the TS buildProofMessage exactly:
//
//	"ton-proof-item-v2/" ‖ int32BE(wc) ‖ addrHash ‖ uint32LE(|domain|) ‖ domain
//	                     ‖ uint64LE(ts) ‖ payload
//
// Integer widths/endianness are spec-exact:
//   - workchain: 4 bytes, big-endian, SIGNED (so -1 -> 0xFFFFFFFF).
//   - domain length: 4 bytes, little-endian, the UTF-8 BYTE length.
//   - timestamp: 8 bytes, little-endian.
func tonBuildMessage(workchain int32, addressHash, domainBytes []byte, timestamp int64, payloadBytes []byte) []byte {
	out := make([]byte, 0, len(tonProofPrefix)+4+len(addressHash)+4+len(domainBytes)+8+len(payloadBytes))
	out = append(out, tonProofPrefix...)

	// workchain — int32 big-endian (signed two's-complement via the uint32 bit
	// pattern; uint32(int32(-1)) == 0xFFFFFFFF, matching DataView.setInt32).
	var wc [4]byte
	binary.BigEndian.PutUint32(wc[:], uint32(workchain))
	out = append(out, wc[:]...)

	out = append(out, addressHash...)

	// domain length — uint32 little-endian over the UTF-8 byte length.
	var dlen [4]byte
	binary.LittleEndian.PutUint32(dlen[:], uint32(len(domainBytes)))
	out = append(out, dlen[:]...)
	out = append(out, domainBytes...)

	// timestamp — uint64 little-endian.
	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], uint64(timestamp))
	out = append(out, ts[:]...)

	out = append(out, payloadBytes...)
	return out
}

// tonProofDigest computes TON Connect's full pre-image and the double hash that
// ed25519 actually signs. Mirrors the TS proofDigest:
//
//	fullMsg = 0xff 0xff ‖ "ton-connect" ‖ sha256(message)
//	digest  = sha256(fullMsg)
func tonProofDigest(message []byte) []byte {
	inner := sha256.Sum256(message)

	full := make([]byte, 0, 2+len(tonConnectPrefix)+len(inner))
	full = append(full, 0xff, 0xff)
	full = append(full, tonConnectPrefix...)
	full = append(full, inner[:]...)

	digest := sha256.Sum256(full)
	return digest[:]
}

// VerifyTon verifies a TON Connect ton_proof login proof (ed25519). Mirrors
// src/ton/verify.ts verifyTon exactly, including check order. Returns true iff
// the ed25519 signature is valid over the reconstructed ton_proof digest AND the
// envelope is bound to the CAIP-122 message (nonce == payload, address ==
// signer). Any other condition -> false. Fails closed; never panics.
func VerifyTon(proof Proof) bool {
	// --- 0. Structural presence: scheme, public key, signature, envelope. ---
	if proof.Scheme != SchemeTonProof {
		return false
	}
	if len(proof.PublicKey) == 0 {
		return false
	}
	if len(proof.Signature) == 0 {
		return false
	}
	if len(proof.Message) == 0 {
		return false
	}
	if len(proof.Address) == 0 {
		return false
	}

	extra, ok := tonReadExtra(proof.Extra)
	if !ok {
		return false
	}

	// --- 1. Binding to the CAIP-122 login message (anti-replay, anti-phishing).
	// ParseSiwxMessage returns an error on malformed input -> fail closed (the
	// Go analog of the TS try/catch around the throwing parseSiwxMessage).
	parsed, err := ParseSiwxMessage(proof.Message)
	if err != nil {
		return false
	}
	// The signed payload MUST be the server-minted nonce carried in the SIWx msg.
	if parsed.Nonce != extra.payload {
		return false
	}
	// The signer MUST be the address embedded in the message.
	if parsed.Address != proof.Address {
		return false
	}

	// --- 2. Decode + length-check the fixed-width cryptographic material. ---
	publicKey, err := hexToBytes(proof.PublicKey)
	if err != nil || len(publicKey) != tonPubKeyLen {
		return false
	}

	signature, err := base64ToBytes(proof.Signature)
	if err != nil || len(signature) != tonSigLen {
		return false
	}

	addressHash, err := hexToBytes(extra.addressHashHex)
	if err != nil || len(addressHash) != tonAddrHashLen {
		return false
	}

	// --- 3. Reconstruct the ton_proof message and the digest the wallet signed.
	domainBytes := []byte(extra.domain)
	payloadBytes := []byte(extra.payload)
	message := tonBuildMessage(extra.workchain, addressHash, domainBytes, extra.timestamp, payloadBytes)
	digest := tonProofDigest(message)

	// --- 4. ed25519 signature check over the 32-byte digest. ---
	return ed25519.Verify(ed25519.PublicKey(publicKey), digest, signature)
}
