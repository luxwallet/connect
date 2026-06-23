package walletconnect

// Bitcoin login-signature verifier. Port of src/bitcoin/verify.ts, mirrored
// byte-for-byte so Hanzo IAM verifies Bitcoin identically to the TypeScript.
//
// Two signing conventions are supported, both verifying a CAIP-122 message
// against a BTC address (P2PKH '1…', P2WPKH 'bc1q…', P2TR 'bc1p…'):
//
//  1. Legacy "Bitcoin Signed Message" — recoverable ECDSA over the double-
//     SHA256 of the magic-prefixed message. Primary path; works for every
//     address type (the wallet picks the key form via the header byte).
//
//  2. BIP-322 "simple" — a virtual to_spend/to_sign transaction pair whose
//     witness is verified with BIP-143 (P2WPKH, ECDSA) or BIP-341 (P2TR,
//     Schnorr) sighash. Used when the signature is a serialized witness stack
//     rather than a 65-byte recoverable sig.
//
// Security posture: fail closed. Every parse/branch returns false on the
// slightest irregularity and the function never panics. The recovered/derived
// address must match the *type* claimed by the proof and be byte-for-byte equal
// to proof.Address.
//
// Crypto comes from github.com/decred/dcrd/dcrec/secp256k1/v4 — its compact-sig
// header format (27 + recid + 4 if compressed) is byte-identical to Bitcoin's
// legacy header, and its ecdsa/schnorr packages give BIP-340/BIP-143/BIP-341
// verification 1:1 with the @noble implementation in the TS.
//
// Every package-level identifier is btc-prefixed: TON and XRP share this flat
// package and generic names would collide.

import (
	"encoding/binary"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD-160 is mandated by Bitcoin's hash160; this is the canonical impl.
)

// btcAddressType is one of the three supported Bitcoin address kinds.
type btcAddressType int

const (
	btcTypeNone btcAddressType = iota
	btcTypeP2PKH
	btcTypeP2WPKH
	btcTypeP2TR
)

// btcHRP is the Bitcoin mainnet bech32 human-readable part.
const btcHRP = "bc"

// btcAddressType determines the address type from an explicit Extra hint, else
// from the address prefix. Mirrors the TS addressType.
func btcAddressTypeOf(proof Proof) btcAddressType {
	if proof.Extra != nil {
		if raw, ok := proof.Extra["addressType"]; ok {
			if s, ok := raw.(string); ok {
				switch strings.ToLower(s) {
				case "p2pkh":
					return btcTypeP2PKH
				case "p2wpkh":
					return btcTypeP2WPKH
				case "p2tr":
					return btcTypeP2TR
				}
			}
		}
	}

	a := proof.Address
	switch {
	case strings.HasPrefix(a, "bc1p"):
		return btcTypeP2TR
	case strings.HasPrefix(a, "bc1q"):
		return btcTypeP2WPKH
	case strings.HasPrefix(a, "1"):
		return btcTypeP2PKH
	}
	return btcTypeNone
}

// ── hashing helpers (btcSha256 / btcSha256d / btcHash160 live in
// bitcoin_bech32.go alongside the address encoders) ──────────────────────────

// btcHash160 = ripemd160(sha256(x)). Lives here because it depends on
// golang.org/x/crypto/ripemd160; the simpler sha helpers are in the bech32 file.
func btcHash160(b []byte) []byte {
	r := ripemd160.New()
	_, _ = r.Write(btcSha256(b))
	return r.Sum(nil)
}

// btcTaggedHash is the BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag)
// || msg…). Mirrors the TS taggedHash.
func btcTaggedHash(tag string, messages ...[]byte) []byte {
	tagHash := btcSha256([]byte(tag))
	buf := make([]byte, 0, len(tagHash)*2)
	buf = append(buf, tagHash...)
	buf = append(buf, tagHash...)
	for _, m := range messages {
		buf = append(buf, m...)
	}
	return btcSha256(buf)
}

// ── address derivation (pubkey → address string) ────────────────────────────

// btcDeriveP2PKH = base58check(0x00 || hash160(pubkey)). Mirrors deriveP2PKH.
func btcDeriveP2PKH(pubkey []byte) string {
	return btcBase58CheckEncode(0x00, btcHash160(pubkey))
}

// btcDeriveP2WPKH = bech32(hrp='bc', witver=0, program=hash160(compressed)).
// Mirrors deriveP2WPKH; ("", false) on failure (TS null).
func btcDeriveP2WPKH(pubkeyCompressed []byte) (string, bool) {
	return btcEncodeSegwitAddress(btcHRP, 0, btcHash160(pubkeyCompressed))
}

// btcTaprootTweak computes the BIP-86 key-path taproot output for an internal
// x-only pubkey:
//
//	t = taggedHash('TapTweak', xonly(P))
//	Q = lift_x(xonly(P)) + t*G   // internal key is the even-Y lift
//	program = xonly(Q)
//
// Returns the 32-byte tweaked x-only program, or (nil, false) on any failure.
// Mirrors taprootTweak.
func btcTaprootTweak(internalXonly []byte) ([]byte, bool) {
	if len(internalXonly) != 32 {
		return nil, false
	}

	// lift_x: even-Y point P with this x coordinate.
	var px secp256k1.FieldVal
	if overflow := px.SetByteSlice(internalXonly); overflow {
		return nil, false // x >= field prime
	}
	var py secp256k1.FieldVal
	if !secp256k1.DecompressY(&px, false, &py) {
		return nil, false // x not on curve
	}
	px.Normalize()
	py.Normalize()
	var P secp256k1.JacobianPoint
	P.X.Set(&px)
	P.Y.Set(&py)
	P.Z.SetInt(1)

	// t = taggedHash('TapTweak', xonly) mod n; reject t == 0.
	var t secp256k1.ModNScalar
	t.SetByteSlice(btcTaggedHash("TapTweak", internalXonly)) // SetByteSlice reduces mod n
	if t.IsZero() {
		return nil, false
	}

	// Q = P + t*G.
	var tG, Q secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&t, &tG)
	secp256k1.AddNonConst(&P, &tG, &Q)
	Q.ToAffine()
	if (Q.X.IsZero() && Q.Y.IsZero()) || Q.Z.IsZero() {
		return nil, false // point at infinity
	}

	qx := Q.X.Bytes()
	out := make([]byte, 32)
	copy(out, qx[:])
	return out, true
}

// btcDeriveP2TR = bech32m(hrp='bc', witver=1, program=taprootTweak(xonly)).
// Mirrors deriveP2TR; ("", false) on failure.
func btcDeriveP2TR(internalXonly []byte) (string, bool) {
	program, ok := btcTaprootTweak(internalXonly)
	if !ok {
		return "", false
	}
	return btcEncodeSegwitAddress(btcHRP, 1, program)
}

// ── Bitcoin var-int / serialization (CompactSize) ───────────────────────────

// btcCompactSize encodes a CompactSize var-int. Mirrors compactSize. Inputs are
// always small here (lengths), so only the 1/3/5/9-byte forms matter; we cover
// all for fidelity. n is a uint64 because Go has no JS number ambiguity.
func btcCompactSize(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n), byte(n >> 8)}
	case n <= 0xffffffff:
		return []byte{0xfe, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
	default:
		out := make([]byte, 9)
		out[0] = 0xff
		binary.LittleEndian.PutUint64(out[1:], n)
		return out
	}
}

// btcU32LE / btcU64LE — little-endian integer encoders. Mirror u32le/u64le.
func btcU32LE(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}

func btcU64LE(n uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return b
}

// btcVarBytes is a length-prefixed (CompactSize) byte string. Mirrors varBytes.
func btcVarBytes(b []byte) []byte {
	out := btcCompactSize(uint64(len(b)))
	return append(out, b...)
}

// btcConcat concatenates byte slices into a fresh buffer. Local helper to keep
// the serialization code readable and 1:1 with the TS concatBytes(...) calls.
func btcConcat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// btcConstTimeStrEq is length-checked, content-comparing string equality
// (addresses are public). Mirrors constTimeStrEq.
func btcConstTimeStrEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ════════════════════════════════════════════════════════════════════════════
// 1. LEGACY "Bitcoin Signed Message" (recoverable ECDSA)
// ════════════════════════════════════════════════════════════════════════════

// btcMsgMagic is the legacy message magic prefix (0x18 = len of the ASCII).
var btcMsgMagic = []byte("\x18Bitcoin Signed Message:\n")

// btcLegacyMessageDigest = sha256d(magic || varint(len) || message). Mirrors
// legacyMessageDigest.
func btcLegacyMessageDigest(message string) []byte {
	msg := []byte(message)
	return btcSha256d(btcConcat(btcMsgMagic, btcCompactSize(uint64(len(msg))), msg))
}

// btcVerifyLegacy verifies a 65-byte recoverable signature [header || r || s]
// over the legacy digest, deriving the address of `typ` and comparing it to
// `address`. Mirrors verifyLegacy.
func btcVerifyLegacy(sig []byte, message, address string, typ btcAddressType) bool {
	if len(sig) != 65 {
		return false
	}
	header := sig[0]
	// 27-30: uncompressed key; 31-34: compressed key. (BIP-137 also defines
	// 35-42 for segwit, but the recovered key form is what matters here, so we
	// accept the canonical 27-34 range and infer compression from it.)
	if header < 27 || header > 34 {
		return false
	}
	compressed := header >= 31

	digest := btcLegacyMessageDigest(message)

	// dcrd's ecdsa.RecoverCompact takes exactly the Bitcoin compact format:
	// <1-byte 27+recid(+4 if compressed)><32 R><32 S>. The header byte in `sig`
	// is already in that encoding, so pass the 65 bytes through unchanged.
	pub, _, err := ecdsa.RecoverCompact(sig, digest)
	if err != nil || pub == nil {
		return false
	}

	// For segwit address types the key MUST be compressed — an uncompressed key
	// cannot back a P2WPKH/P2TR script, so reject rather than silently coercing.
	if (typ == btcTypeP2WPKH || typ == btcTypeP2TR) && !compressed {
		return false
	}

	var derived string
	var ok bool
	switch typ {
	case btcTypeP2PKH:
		// P2PKH commits to the exact key encoding chosen by the header byte.
		var encoded []byte
		if compressed {
			encoded = pub.SerializeCompressed()
		} else {
			encoded = pub.SerializeUncompressed()
		}
		derived = btcDeriveP2PKH(encoded)
		ok = true
	case btcTypeP2WPKH:
		derived, ok = btcDeriveP2WPKH(pub.SerializeCompressed())
	case btcTypeP2TR:
		// Internal key = x-only of the recovered (compressed) key.
		xonly := pub.SerializeCompressed()[1:]
		derived, ok = btcDeriveP2TR(xonly)
	default:
		return false
	}

	return ok && btcConstTimeStrEq(derived, address)
}

// ════════════════════════════════════════════════════════════════════════════
// 2. BIP-322 "simple"
// ════════════════════════════════════════════════════════════════════════════

// btcParseWitness parses a serialized witness stack: count, then length-
// prefixed elements. Mirrors parseWitness (count in 1..4, no trailing garbage).
// Returns (nil, false) on any irregularity.
func btcParseWitness(buf []byte) ([][]byte, bool) {
	off := 0
	readCompact := func() (int, bool) {
		if off >= len(buf) {
			return 0, false
		}
		first := buf[off]
		off++
		if first < 0xfd {
			return int(first), true
		}
		if first == 0xfd {
			if off+2 > len(buf) {
				return 0, false
			}
			v := int(buf[off]) | int(buf[off+1])<<8
			off += 2
			return v, true
		}
		if first == 0xfe {
			if off+4 > len(buf) {
				return 0, false
			}
			v := int(buf[off]) | int(buf[off+1])<<8 | int(buf[off+2])<<16 | int(buf[off+3])<<24
			off += 4
			return v, true
		}
		return 0, false // 64-bit lengths never appear in witness logins
	}

	count, ok := readCompact()
	if !ok || count < 1 || count > 4 {
		return nil, false
	}
	items := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		length, ok := readCompact()
		if !ok || length < 0 || off+length > len(buf) {
			return nil, false
		}
		items = append(items, buf[off:off+length])
		off += length
	}
	if off != len(buf) {
		return nil, false // no trailing garbage
	}
	return items, true
}

// btcScriptPubKeyP2WPKH = OP_0 PUSH20 <hash160>. Mirrors scriptPubKeyP2WPKH.
func btcScriptPubKeyP2WPKH(hash160Pub []byte) []byte {
	return btcConcat([]byte{0x00, 0x14}, hash160Pub)
}

// btcScriptPubKeyP2TR = OP_1 PUSH32 <tweaked xonly>. Mirrors scriptPubKeyP2TR.
func btcScriptPubKeyP2TR(programXonly []byte) []byte {
	return btcConcat([]byte{0x51, 0x20}, programXonly)
}

// btcToSpendTxid builds the BIP-322 to_spend txid = sha256d(serialization
// without witness). Mirrors toSpendTxid.
func btcToSpendTxid(message string, scriptPubKey []byte) []byte {
	msgHash := btcTaggedHash("BIP0322-signed-message", []byte(message))
	scriptSig := btcConcat([]byte{0x00, 0x20}, msgHash) // OP_0 PUSH32

	ser := btcConcat(
		btcU32LE(0),          // nVersion = 0
		btcCompactSize(1),    // vin count
		make([]byte, 32),     // prevout hash = 0
		btcU32LE(0xffffffff), // prevout index = 0xFFFFFFFF
		btcVarBytes(scriptSig),
		btcU32LE(0),       // nSequence = 0
		btcCompactSize(1), // vout count
		btcU64LE(0),       // value = 0
		btcVarBytes(scriptPubKey),
		btcU32LE(0), // nLockTime = 0
	)
	return btcSha256d(ser)
}

// btcBip143SighashP2WPKH is the BIP-143 sighash (SIGHASH_ALL) for the single
// input of the BIP-322 to_sign tx (P2WPKH). Mirrors bip143SighashP2WPKH.
func btcBip143SighashP2WPKH(toSpendTxid, hash160Pub []byte) []byte {
	outpoint := btcConcat(toSpendTxid, btcU32LE(0)) // to_spend:0
	nSequence := btcU32LE(0)
	hashPrevouts := btcSha256d(outpoint)
	hashSequence := btcSha256d(nSequence)

	scriptCode := btcConcat(
		[]byte{0x19, 0x76, 0xa9, 0x14}, // len(25) OP_DUP OP_HASH160 PUSH20
		hash160Pub,
		[]byte{0x88, 0xac}, // OP_EQUALVERIFY OP_CHECKSIG
	)

	// to_sign single output: value=0, scriptPubKey = OP_RETURN (0x6a).
	output := btcConcat(btcU64LE(0), btcVarBytes([]byte{0x6a}))
	hashOutputs := btcSha256d(output)

	preimage := btcConcat(
		btcU32LE(0), // nVersion = 0
		hashPrevouts,
		hashSequence,
		outpoint,
		scriptCode,
		btcU64LE(0), // amount of the spent output = 0
		nSequence,
		hashOutputs,
		btcU32LE(0), // nLockTime = 0
		btcU32LE(1), // SIGHASH_ALL
	)
	return btcSha256d(preimage)
}

// btcBip341SighashP2TR is the BIP-341 (taproot key-path) sighash with
// SIGHASH_DEFAULT (0x00). Single P2TR input, single OP_RETURN output. Mirrors
// bip341SighashP2TR.
func btcBip341SighashP2TR(toSpendTxid, scriptPubKey []byte) []byte {
	outpoint := btcConcat(toSpendTxid, btcU32LE(0))
	nSequence := btcU32LE(0)

	shaPrevouts := btcSha256(outpoint)
	shaAmounts := btcSha256(btcU64LE(0)) // single spent amount = 0
	shaScriptPubkeys := btcSha256(btcVarBytes(scriptPubKey))
	shaSequences := btcSha256(nSequence)
	output := btcConcat(btcU64LE(0), btcVarBytes([]byte{0x6a})) // value=0, OP_RETURN
	shaOutputs := btcSha256(output)

	epoch := []byte{0x00}
	hashType := []byte{0x00}  // SIGHASH_DEFAULT
	spendType := []byte{0x00} // no annex, key-path
	inputIndex := btcU32LE(0)

	sigMsg := btcConcat(
		hashType,
		btcU32LE(0), // nVersion = 0
		btcU32LE(0), // nLockTime = 0
		shaPrevouts,
		shaAmounts,
		shaScriptPubkeys,
		shaSequences,
		shaOutputs,
		spendType,
		inputIndex,
	)
	// BIP-341: tagged hash "TapSighash" over (epoch || sigMsg).
	return btcTaggedHash("TapSighash", btcConcat(epoch, sigMsg))
}

// btcVerifyBip322P2WPKH verifies a BIP-322 simple P2WPKH witness. Mirrors
// verifyBip322P2WPKH.
func btcVerifyBip322P2WPKH(witness [][]byte, message, address string) bool {
	// Witness stack for P2WPKH is exactly [signature, pubkey].
	if len(witness) != 2 {
		return false
	}
	sigBytes := witness[0]
	pubkey := witness[1]
	if len(pubkey) != 33 || (pubkey[0] != 0x02 && pubkey[0] != 0x03) {
		return false
	}

	// Address binding: the witness pubkey must hash to the claimed P2WPKH address.
	h160 := btcHash160(pubkey)
	derived, ok := btcDeriveP2WPKH(pubkey)
	if !ok || !btcConstTimeStrEq(derived, address) {
		return false
	}

	// Strip the trailing SIGHASH byte from the DER ECDSA signature.
	if len(sigBytes) < 1 {
		return false
	}
	sighashType := sigBytes[len(sigBytes)-1]
	der := sigBytes[:len(sigBytes)-1]
	// BIP-322 simple for single-key uses SIGHASH_ALL.
	if sighashType != 0x01 {
		return false
	}

	txid := btcToSpendTxid(message, btcScriptPubKeyP2WPKH(h160))
	sighash := btcBip143SighashP2WPKH(txid, h160)

	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return false
	}
	// Reject high-S (BIP-146 / consensus-standardness, anti-malleability).
	s := sig.S()
	if s.IsOverHalfOrder() {
		return false
	}
	pub, err := secp256k1.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	return sig.Verify(sighash, pub)
}

// btcVerifyBip322P2TR verifies a BIP-322 simple P2TR key-path witness. Mirrors
// verifyBip322P2TR.
func btcVerifyBip322P2TR(witness [][]byte, message, address string) bool {
	// Key-path spend: witness is exactly [schnorr_sig].
	if len(witness) != 1 {
		return false
	}
	witnessSig := witness[0]

	// Parse a 64- or 65-byte BIP-340 schnorr sig (optional trailing sighash).
	var schnorrSig []byte
	var sighashType byte
	switch len(witnessSig) {
	case 64:
		schnorrSig = witnessSig
		sighashType = 0x00
	case 65:
		schnorrSig = witnessSig[:64]
		sighashType = witnessSig[64]
	default:
		return false
	}
	if sighashType != 0x00 { // SIGHASH_DEFAULT only
		return false
	}

	// Decode the bech32m program (the 32-byte x-only output key) from the
	// claimed address, re-validating the checksum by re-encoding (fail closed).
	program, ok := btcDecodeP2TRProgram(address)
	if !ok {
		return false
	}

	txid := btcToSpendTxid(message, btcScriptPubKeyP2TR(program))
	sighash := btcBip341SighashP2TR(txid, btcScriptPubKeyP2TR(program))

	// BIP-340 schnorr verify of (schnorrSig) over `sighash` against the x-only
	// output key `program`. Mirrors the TS schnorr.verify(sig, msg, xonly).
	return btcSchnorrVerifyBIP340(schnorrSig, sighash, program)
}

// btcSchnorrVerifyBIP340 verifies a 64-byte BIP-340 schnorr signature (r‖s)
// over a 32-byte message `m` against a 32-byte x-only public key `px`.
//
// CAUTION: this is implemented inline rather than via dcrd's
// secp256k1/v4/schnorr package, because that package implements EC-Schnorr-DCRv0
// (challenge = BLAKE-256(r‖m)), NOT Bitcoin's BIP-340 (challenge =
// taggedHash("BIP0340/challenge", r‖px‖m) with SHA-256). The underlying
// secp256k1 field/scalar/point math is reused from dcrd; only the challenge
// construction differs. This matches @noble/curves `schnorr.verify` 1:1.
//
// Algorithm (BIP-340 §Verify):
//
//	P  = lift_x(int(px))                 // even-Y; fail if not on curve
//	r  = int(sig[0:32]);  fail if r >= p
//	s  = int(sig[32:64]); fail if s >= n
//	e  = int(taggedHash("BIP0340/challenge", r||px||m)) mod n
//	R  = s*G - e*P                       // fail if infinity / R.y odd / R.x != r
func btcSchnorrVerifyBIP340(sig, m, px []byte) bool {
	if len(sig) != 64 || len(m) != 32 || len(px) != 32 {
		return false
	}

	// P = lift_x(px): the even-Y point with x-coordinate px.
	var pxFv secp256k1.FieldVal
	if overflow := pxFv.SetByteSlice(px); overflow {
		return false // px >= field prime
	}
	var pyFv secp256k1.FieldVal
	if !secp256k1.DecompressY(&pxFv, false, &pyFv) {
		return false // px not on curve
	}
	pxFv.Normalize()
	pyFv.Normalize()
	var P secp256k1.JacobianPoint
	P.X.Set(&pxFv)
	P.Y.Set(&pyFv)
	P.Z.SetInt(1)

	// r = sig[0:32] as a field element; fail if r >= p.
	rBytes := sig[0:32]
	var rFv secp256k1.FieldVal
	if overflow := rFv.SetByteSlice(rBytes); overflow {
		return false // r >= field prime
	}
	rFv.Normalize()

	// s = sig[32:64] as a scalar mod n; fail if s >= n (no silent reduction).
	var sScalar secp256k1.ModNScalar
	if overflow := sScalar.SetByteSlice(sig[32:64]); overflow {
		return false // s >= group order
	}

	// e = int(taggedHash("BIP0340/challenge", r || px || m)) mod n.
	var eScalar secp256k1.ModNScalar
	eScalar.SetByteSlice(btcTaggedHash("BIP0340/challenge", rBytes, px, m)) // reduces mod n

	// R = s*G - e*P  =  s*G + (-e)*P.
	var negE secp256k1.ModNScalar
	negE.Set(&eScalar).Negate()
	var sG, eP, R secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&sScalar, &sG)
	secp256k1.ScalarMultNonConst(&negE, &P, &eP)
	secp256k1.AddNonConst(&sG, &eP, &R)

	// Fail if R is the point at infinity.
	if (R.X.IsZero() && R.Y.IsZero()) || R.Z.IsZero() {
		return false
	}
	R.ToAffine()
	// Fail if R.y is odd.
	if R.Y.IsOdd() {
		return false
	}
	// Verified iff R.x == r.
	return R.X.Equals(&rFv)
}

// btcDecodeP2TRProgram decodes a bech32m P2TR ('bc1p…') address to its 32-byte
// witness program. Re-validates the checksum by re-encoding and comparing (fail
// closed). Mirrors decodeP2TRProgram.
func btcDecodeP2TRProgram(address string) ([]byte, bool) {
	lower := strings.ToLower(address)
	// Reject mixed case (per BIP-173): the original must be all-lower or all-upper.
	if lower != address && strings.ToUpper(address) != address {
		return nil, false
	}
	pos := strings.LastIndex(lower, "1")
	if pos < 1 {
		return nil, false
	}
	hrp := lower[:pos]
	if hrp != btcHRP {
		return nil, false
	}
	dataPart := lower[pos+1:]
	if len(dataPart) < 7 { // 1 (witver) + program + 6 checksum
		return nil, false
	}

	values := make([]int, 0, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		v := strings.IndexByte(btcCharset, dataPart[i])
		if v == -1 {
			return nil, false
		}
		values = append(values, v)
	}
	witver := values[0]
	if witver != 1 { // only taproot here
		return nil, false
	}

	// Convert 5-bit data (excluding witver and 6-byte checksum) -> 8-bit program.
	data5 := values[1 : len(values)-6]
	program := btcConvert5to8(data5)
	if program == nil || len(program) != 32 {
		return nil, false
	}

	// Re-encode with bech32m and compare to validate the checksum.
	reencoded, ok := btcEncodeSegwitAddress(btcHRP, 1, program)
	if !ok || reencoded != lower {
		return nil, false
	}
	return program, true
}

// ════════════════════════════════════════════════════════════════════════════
// dispatch
// ════════════════════════════════════════════════════════════════════════════

// VerifyBitcoin verifies a Bitcoin login-message signature: legacy "Bitcoin
// Signed Message" (recoverable ECDSA) plus BIP-322 simple (P2WPKH/P2TR), with
// P2PKH/P2WPKH/P2TR address binding. Port of src/bitcoin/verify.ts. Fails
// closed: any parse/branch irregularity returns false, and it never panics.
func VerifyBitcoin(proof Proof) bool {
	typ := btcAddressTypeOf(proof)
	if typ == btcTypeNone {
		return false
	}

	// proof.Signature is base64 here (TS uses base64ToBytes, not the
	// hex-or-base64 heuristic). Mirror that exactly.
	sig, err := base64ToBytes(proof.Signature)
	if err != nil {
		return false
	}
	if len(sig) == 0 {
		return false
	}

	// Shape-based dispatch (exactly one path per shape):
	//   • 65 bytes with a valid header → legacy recoverable ECDSA.
	//   • otherwise → BIP-322 simple (serialized witness stack).
	header := sig[0]
	looksLegacy := len(sig) == 65 && header >= 27 && header <= 34

	if looksLegacy {
		return btcVerifyLegacy(sig, proof.Message, proof.Address, typ)
	}

	// BIP-322 simple — only P2WPKH and P2TR are defined for key-path here.
	witness, ok := btcParseWitness(sig)
	if !ok {
		return false
	}
	switch typ {
	case btcTypeP2WPKH:
		return btcVerifyBip322P2WPKH(witness, proof.Message, proof.Address)
	case btcTypeP2TR:
		return btcVerifyBip322P2TR(witness, proof.Message, proof.Address)
	}
	// BIP-322 for P2PKH is not standardized for "simple"; legacy covers it.
	return false
}
