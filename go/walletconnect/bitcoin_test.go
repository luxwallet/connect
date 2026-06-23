package walletconnect

// Mirrors src/__tests__/bitcoin.test.ts. Every test reproduces the Bitcoin
// signing + address derivation INDEPENDENTLY of the verifier (no shared
// internals): if the two ever drift, the round-trip "accepts a valid proof"
// tests fail — the whole point of mirroring rather than importing verifier
// internals.
//
// Coverage:
//   - Legacy "Bitcoin Signed Message" (recoverable ECDSA) for P2PKH, P2WPKH,
//     P2TR (BIP-86).
//   - BIP-322 "simple" for P2WPKH (ECDSA / BIP-143) and P2TR key-path
//     (Schnorr / BIP-341).
//   - Tamper / wrong-address / wrong-type negatives (fail closed).
//   - Anchors: the BIP-322 message hash + to_spend txid + P2WPKH derivation are
//     pinned to the official Bitcoin Core BIP-322 test vectors.
//
// CRITICAL: the P2TR schnorr signer below is a from-scratch BIP-340 signer
// (tagged-hash challenge, SHA-256). It does NOT use dcrd's
// secp256k1/v4/schnorr, which is EC-Schnorr-DCRv0 (BLAKE-256) and would not
// interoperate with Bitcoin or the TS verifier.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ── independent wallet-side crypto helpers ───────────────────────────────────

func testBtcSha256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func testBtcSha256d(b []byte) []byte {
	return testBtcSha256(testBtcSha256(b))
}

func testBtcConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func testBtcTaggedHash(tag string, m ...[]byte) []byte {
	t := testBtcSha256([]byte(tag))
	return testBtcSha256(testBtcConcat(append([][]byte{t, t}, m...)...))
}

func testBtcCompactSize(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfd, byte(n), byte(n >> 8)}
	default:
		return []byte{0xfe, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
	}
}

func testBtcU32LE(n uint32) []byte {
	return []byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
}

func testBtcU64LE(n uint64) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(n)
		n >>= 8
	}
	return b
}

func testBtcVarBytes(b []byte) []byte {
	return testBtcConcat(testBtcCompactSize(uint64(len(b))), b)
}

func testBtcToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func testBtcHexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// testBtcPrivFromHex builds a private key from a 32-byte hex string.
func testBtcPrivFromHex(t *testing.T, h string) *secp256k1.PrivateKey {
	t.Helper()
	return secp256k1.PrivKeyFromBytes(testBtcHexToBytes(t, h))
}

// ── independent address derivations (must match the verifier's) ──────────────

func testBtcP2PKH(t *testing.T, pubkey []byte) string {
	t.Helper()
	// Reuse the verifier's encoders for base58check; they are independently
	// checked against KAT vectors below, so this is not circular.
	return btcBase58CheckEncode(0x00, btcHash160(pubkey))
}

func testBtcP2WPKH(t *testing.T, pubCompressed []byte) string {
	t.Helper()
	addr, ok := btcEncodeSegwitAddress("bc", 0, btcHash160(pubCompressed))
	if !ok {
		t.Fatal("P2WPKH encode failed")
	}
	return addr
}

// testBtcTaprootTweak computes the BIP-86 tweaked output x-only key from an
// internal x-only key, independently of the verifier's btcTaprootTweak.
func testBtcTaprootTweak(t *testing.T, internalXonly []byte) []byte {
	t.Helper()
	var px secp256k1.FieldVal
	if px.SetByteSlice(internalXonly) {
		t.Fatal("internal x overflow")
	}
	var py secp256k1.FieldVal
	if !secp256k1.DecompressY(&px, false, &py) {
		t.Fatal("internal x not on curve")
	}
	px.Normalize()
	py.Normalize()
	var P secp256k1.JacobianPoint
	P.X.Set(&px)
	P.Y.Set(&py)
	P.Z.SetInt(1)

	var tw secp256k1.ModNScalar
	tw.SetByteSlice(testBtcTaggedHash("TapTweak", internalXonly))
	if tw.IsZero() {
		t.Fatal("tweak is zero")
	}
	var tG, Q secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&tw, &tG)
	secp256k1.AddNonConst(&P, &tG, &Q)
	Q.ToAffine()
	qx := Q.X.Bytes()
	return append([]byte{}, qx[:]...)
}

func testBtcP2TR(t *testing.T, internalXonly []byte) (address string, program []byte) {
	t.Helper()
	program = testBtcTaprootTweak(t, internalXonly)
	addr, ok := btcEncodeSegwitAddress("bc", 1, program)
	if !ok {
		t.Fatal("P2TR encode failed")
	}
	return addr, program
}

// ── legacy "Bitcoin Signed Message" signer ───────────────────────────────────

func testBtcLegacyDigest(message string) []byte {
	msg := []byte(message)
	magic := []byte("\x18Bitcoin Signed Message:\n")
	return testBtcSha256d(testBtcConcat(magic, testBtcCompactSize(uint64(len(msg))), msg))
}

// testBtcSignLegacy produces a 65-byte [header||r||s] legacy signature using
// dcrd's SignCompact, whose header byte (27+recid(+4 if compressed)) is exactly
// Bitcoin's legacy header.
func testBtcSignLegacy(priv *secp256k1.PrivateKey, message string, compressed bool) []byte {
	digest := testBtcLegacyDigest(message)
	return ecdsa.SignCompact(priv, digest, compressed)
}

// ── BIP-322 simple signers (sign exactly the verifier's sighash) ─────────────

func testBtcToSpendTxid(message string, scriptPubKey []byte) []byte {
	msgHash := testBtcTaggedHash("BIP0322-signed-message", []byte(message))
	scriptSig := testBtcConcat([]byte{0x00, 0x20}, msgHash)
	ser := testBtcConcat(
		testBtcU32LE(0),
		testBtcCompactSize(1),
		make([]byte, 32),
		testBtcU32LE(0xffffffff),
		testBtcVarBytes(scriptSig),
		testBtcU32LE(0),
		testBtcCompactSize(1),
		testBtcU64LE(0),
		testBtcVarBytes(scriptPubKey),
		testBtcU32LE(0),
	)
	return testBtcSha256d(ser)
}

func testBtcBip143SighashP2WPKH(txid, h160 []byte) []byte {
	outpoint := testBtcConcat(txid, testBtcU32LE(0))
	nSequence := testBtcU32LE(0)
	hashPrevouts := testBtcSha256d(outpoint)
	hashSequence := testBtcSha256d(nSequence)
	scriptCode := testBtcConcat([]byte{0x19, 0x76, 0xa9, 0x14}, h160, []byte{0x88, 0xac})
	output := testBtcConcat(testBtcU64LE(0), testBtcVarBytes([]byte{0x6a}))
	hashOutputs := testBtcSha256d(output)
	preimage := testBtcConcat(
		testBtcU32LE(0),
		hashPrevouts,
		hashSequence,
		outpoint,
		scriptCode,
		testBtcU64LE(0),
		nSequence,
		hashOutputs,
		testBtcU32LE(0),
		testBtcU32LE(1),
	)
	return testBtcSha256d(preimage)
}

func testBtcBip341SighashP2TR(txid, scriptPubKey []byte) []byte {
	outpoint := testBtcConcat(txid, testBtcU32LE(0))
	nSequence := testBtcU32LE(0)
	shaPrevouts := testBtcSha256(outpoint)
	shaAmounts := testBtcSha256(testBtcU64LE(0))
	shaScriptPubkeys := testBtcSha256(testBtcVarBytes(scriptPubKey))
	shaSequences := testBtcSha256(nSequence)
	output := testBtcConcat(testBtcU64LE(0), testBtcVarBytes([]byte{0x6a}))
	shaOutputs := testBtcSha256(output)
	sigMsg := testBtcConcat(
		[]byte{0x00}, // hash_type SIGHASH_DEFAULT
		testBtcU32LE(0),
		testBtcU32LE(0),
		shaPrevouts,
		shaAmounts,
		shaScriptPubkeys,
		shaSequences,
		shaOutputs,
		[]byte{0x00}, // spend_type
		testBtcU32LE(0),
	)
	return testBtcTaggedHash("TapSighash", testBtcConcat([]byte{0x00}, sigMsg))
}

func testBtcSerializeWitness(items [][]byte) []byte {
	out := testBtcCompactSize(uint64(len(items)))
	for _, it := range items {
		out = testBtcConcat(out, testBtcVarBytes(it))
	}
	return out
}

// testBtcSignBip322P2WPKH produces a BIP-322 simple P2WPKH witness
// [DER-sig||SIGHASH_ALL, pubkey]. dcrd's ecdsa.Sign is RFC-6979 + low-S, which
// the verifier requires.
func testBtcSignBip322P2WPKH(priv *secp256k1.PrivateKey, message string) []byte {
	pub := priv.PubKey().SerializeCompressed()
	h160 := btcHash160(pub)
	spk := testBtcConcat([]byte{0x00, 0x14}, h160)
	txid := testBtcToSpendTxid(message, spk)
	sighash := testBtcBip143SighashP2WPKH(txid, h160)
	sig := ecdsa.Sign(priv, sighash) // RFC-6979, canonical low-S
	der := testBtcConcat(sig.Serialize(), []byte{0x01})
	return testBtcSerializeWitness([][]byte{der, pub})
}

// testBtcSignBip322P2TR produces a BIP-322 simple P2TR key-path witness
// [schnorr_sig], signing the BIP-341 sighash with the BIP-86 tweaked key.
func testBtcSignBip322P2TR(t *testing.T, priv *secp256k1.PrivateKey, message string) (sig []byte, address string) {
	t.Helper()
	internalXonly := priv.PubKey().SerializeCompressed()[1:]
	addr, program := testBtcP2TR(t, internalXonly)
	spk := testBtcConcat([]byte{0x51, 0x20}, program)
	txid := testBtcToSpendTxid(message, spk)
	sighash := testBtcBip341SighashP2TR(txid, spk)

	// BIP-86 tweaked private key: d_even (negate d if internal P has odd Y),
	// then add t.
	d := priv.Key // ModNScalar copy
	// Determine parity of internal P = d*G.
	var Pj secp256k1.JacobianPoint
	dCopy := d
	secp256k1.ScalarBaseMultNonConst(&dCopy, &Pj)
	Pj.ToAffine()
	if Pj.Y.IsOdd() {
		d.Negate()
	}
	var tw secp256k1.ModNScalar
	tw.SetByteSlice(testBtcTaggedHash("TapTweak", internalXonly))
	d.Add(&tw)
	tweakedBytes := d.Bytes()

	schnorrSig := testBtcSchnorrSignBIP340(t, tweakedBytes[:], sighash)
	return testBtcSerializeWitness([][]byte{schnorrSig}), addr
}

// testBtcSchnorrSignBIP340 is a from-scratch BIP-340 signer (aux_rand = 0).
// Produces a 64-byte (r||s) signature over the 32-byte message `m` with the
// 32-byte secret `d`. Tagged-hash challenge (SHA-256), matching the verifier
// and @noble/curves.
func testBtcSchnorrSignBIP340(t *testing.T, dBytes, m []byte) []byte {
	t.Helper()
	if len(dBytes) != 32 || len(m) != 32 {
		t.Fatal("bad BIP-340 sign input length")
	}
	var d secp256k1.ModNScalar
	if d.SetByteSlice(dBytes) || d.IsZero() {
		t.Fatal("invalid d for BIP-340 sign")
	}
	// P = d*G; if P.y is odd, d = n - d so that P has even Y.
	var P secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&d, &P)
	P.ToAffine()
	if P.Y.IsOdd() {
		d.Negate()
		secp256k1.ScalarBaseMultNonConst(&d, &P)
		P.ToAffine()
	}
	pxBytes := P.X.Bytes()
	dBytesEven := d.Bytes()

	// t = d XOR taggedHash("BIP0340/aux", aux_rand=0^32).
	aux := make([]byte, 32)
	auxHash := testBtcTaggedHash("BIP0340/aux", aux)
	tArr := make([]byte, 32)
	for i := 0; i < 32; i++ {
		tArr[i] = dBytesEven[i] ^ auxHash[i]
	}
	// rand = taggedHash("BIP0340/nonce", t || px || m).
	randHash := testBtcTaggedHash("BIP0340/nonce", tArr, pxBytes[:], m)
	var k secp256k1.ModNScalar
	if k.SetByteSlice(randHash) || k.IsZero() {
		t.Fatal("invalid nonce for BIP-340 sign")
	}
	// R = k*G; if R.y is odd, k = n - k.
	var R secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&k, &R)
	R.ToAffine()
	if R.Y.IsOdd() {
		k.Negate()
	}
	rxBytes := R.X.Bytes()
	// e = int(taggedHash("BIP0340/challenge", rx || px || m)) mod n.
	var e secp256k1.ModNScalar
	e.SetByteSlice(testBtcTaggedHash("BIP0340/challenge", rxBytes[:], pxBytes[:], m))
	// s = (k + e*d) mod n.
	var ed secp256k1.ModNScalar
	ed.Mul2(&e, &d)
	var s secp256k1.ModNScalar
	s.Set(&k).Add(&ed)
	sBytes := s.Bytes()

	out := make([]byte, 64)
	copy(out[0:32], rxBytes[:])
	copy(out[32:64], sBytes[:])
	return out
}

// ── fixtures ─────────────────────────────────────────────────────────────────

// makeMessage builds the same CAIP-122 login message the TS test uses
// (domain hanzo.id, nonce abc123XYZ789, now = 2026-01-01T00:00:00Z).
func testBtcMakeMessage(t *testing.T, address string) string {
	t.Helper()
	stmt := "Sign in to Hanzo"
	c := newChallenge(challengeOpts{
		domain:    "hanzo.id",
		uri:       "https://hanzo.id/login",
		statement: &stmt,
		nonce:     "abc123XYZ789",
		nowMs:     1767225600000, // Date.UTC(2026, 0, 1)
	})
	msg, err := BuildSiwxMessage(BuildParams{Challenge: c, Address: address, Chain: ChainBitcoin})
	if err != nil {
		t.Fatalf("BuildSiwxMessage: %v", err)
	}
	return msg
}

// testBtcPriv is a fixed key (d = 42) so failures are reproducible. Matches the
// TS PRIV.
func testBtcPriv(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	b := make([]byte, 32)
	b[31] = 0x2a
	return secp256k1.PrivKeyFromBytes(b)
}

// ════════════════════════════════════════════════════════════════════════════
// anchors — official Bitcoin Core BIP-322 vectors
// ════════════════════════════════════════════════════════════════════════════

func TestBitcoinBip322Anchors(t *testing.T) {
	const addr = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
	// The known WIF private key for that address (extracted body).
	wifPriv := testBtcHexToBytes(t, "bb051cd0dda0246f33c5a9e133ebd8e7bc02a92af6c41adc131ccd7826c5b004")
	pub := secp256k1.PrivKeyFromBytes(wifPriv).PubKey().SerializeCompressed()

	// P2WPKH derivation anchor.
	if got := testBtcP2WPKH(t, pub); got != addr {
		t.Fatalf("P2WPKH derivation = %q, want %q", got, addr)
	}

	// BIP0322-signed-message tagged-hash anchors.
	if got := hex.EncodeToString(testBtcTaggedHash("BIP0322-signed-message", []byte(""))); got !=
		"c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1" {
		t.Fatalf("tagged-hash(\"\") = %s", got)
	}
	if got := hex.EncodeToString(testBtcTaggedHash("BIP0322-signed-message", []byte("Hello World"))); got !=
		"f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a" {
		t.Fatalf("tagged-hash(\"Hello World\") = %s", got)
	}

	// to_spend txid anchors (displayed reversed, the Bitcoin display convention).
	spk := testBtcConcat([]byte{0x00, 0x14}, btcHash160(pub))
	display := func(b []byte) string {
		r := make([]byte, len(b))
		for i := range b {
			r[len(b)-1-i] = b[i]
		}
		return hex.EncodeToString(r)
	}
	if got := display(testBtcToSpendTxid("", spk)); got !=
		"c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7" {
		t.Fatalf("to_spend txid(\"\") = %s", got)
	}
	if got := display(testBtcToSpendTxid("Hello World", spk)); got !=
		"b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b" {
		t.Fatalf("to_spend txid(\"Hello World\") = %s", got)
	}

	// The verifier's own serialization must agree with the independent one.
	if !bytes.Equal(btcToSpendTxid("Hello World", btcScriptPubKeyP2WPKH(btcHash160(pub))),
		testBtcToSpendTxid("Hello World", spk)) {
		t.Fatal("verifier to_spend txid disagrees with independent vector")
	}
	if !bytes.Equal(btcTaggedHash("BIP0322-signed-message", []byte("Hello World")),
		testBtcTaggedHash("BIP0322-signed-message", []byte("Hello World"))) {
		t.Fatal("verifier tagged-hash disagrees with independent vector")
	}
}

// Base58Check KAT: the canonical Bitcoin genesis-style address derivation.
func TestBitcoinBase58CheckKnownAnswer(t *testing.T) {
	// hash160 of the uncompressed public key of priv=1 -> known P2PKH address.
	// Use a fixed pubkey-hash with a published encoding instead:
	//   version 0x00 || 20 zero bytes -> "1111111111111111111114oLvT2"
	got := btcBase58CheckEncode(0x00, make([]byte, 20))
	const want = "1111111111111111111114oLvT2"
	if got != want {
		t.Fatalf("btcBase58CheckEncode(0x00, 0^20) = %q, want %q", got, want)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// legacy "Bitcoin Signed Message"
// ════════════════════════════════════════════════════════════════════════════

func TestBitcoinLegacyP2PKHCompressed(t *testing.T) {
	priv := testBtcPriv(t)
	pubC := priv.PubKey().SerializeCompressed()
	address := testBtcP2PKH(t, pubC)
	message := testBtcMakeMessage(t, address)
	sig := testBtcSignLegacy(priv, message, true)

	proof := Proof{
		Chain:     ChainBitcoin,
		Scheme:    SchemeBIP322,
		Address:   address,
		Message:   message,
		Signature: testBtcToBase64(sig),
	}
	if !VerifyBitcoin(proof) {
		t.Fatal("VerifyBitcoin(valid P2PKH compressed) = false, want true")
	}

	// Tamper the signature (flip a byte in r).
	bad := append([]byte{}, sig...)
	bad[5] ^= 0xff
	if VerifyBitcoin(withSig(proof, bad)) {
		t.Fatal("VerifyBitcoin(tampered sig) = true, want false")
	}

	// Tamper the message.
	if VerifyBitcoin(withMessage(proof, message+" ")) {
		t.Fatal("VerifyBitcoin(tampered message) = true, want false")
	}

	// Wrong address (different key's P2PKH).
	other := testBtcPrivFromHex(t, repeatHex("11", 32)).PubKey().SerializeCompressed()
	if VerifyBitcoin(withAddress(proof, testBtcP2PKH(t, other))) {
		t.Fatal("VerifyBitcoin(wrong address) = true, want false")
	}
}

func TestBitcoinLegacyP2PKHUncompressed(t *testing.T) {
	priv := testBtcPriv(t)
	pubU := priv.PubKey().SerializeUncompressed()
	address := testBtcP2PKH(t, pubU)
	message := testBtcMakeMessage(t, address)
	sig := testBtcSignLegacy(priv, message, false)

	if !VerifyBitcoin(Proof{
		Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: address, Message: message,
		Signature: testBtcToBase64(sig),
	}) {
		t.Fatal("VerifyBitcoin(valid P2PKH uncompressed) = false, want true")
	}

	// The compressed-key address must NOT verify against an uncompressed-header sig.
	pubC := priv.PubKey().SerializeCompressed()
	cAddr := testBtcP2PKH(t, pubC)
	cMsg := testBtcMakeMessage(t, cAddr)
	uncompSig := testBtcSignLegacy(priv, cMsg, false)
	if VerifyBitcoin(Proof{
		Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: cAddr, Message: cMsg,
		Signature: testBtcToBase64(uncompSig),
	}) {
		t.Fatal("VerifyBitcoin(compressed addr vs uncompressed-header sig) = true, want false")
	}
}

func TestBitcoinLegacyP2WPKH(t *testing.T) {
	priv := testBtcPriv(t)
	pubC := priv.PubKey().SerializeCompressed()
	address := testBtcP2WPKH(t, pubC)
	message := testBtcMakeMessage(t, address)
	sig := testBtcSignLegacy(priv, message, true)

	if !VerifyBitcoin(Proof{
		Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: address, Message: message,
		Signature: testBtcToBase64(sig),
	}) {
		t.Fatal("VerifyBitcoin(valid P2WPKH legacy) = false, want true")
	}

	// Uncompressed header can't back a segwit address -> reject.
	uncompSig := testBtcSignLegacy(priv, message, false)
	if VerifyBitcoin(Proof{
		Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: address, Message: message,
		Signature: testBtcToBase64(uncompSig),
	}) {
		t.Fatal("VerifyBitcoin(P2WPKH uncompressed header) = true, want false")
	}

	// A P2WPKH address from a DIFFERENT key must not verify against this sig.
	other := testBtcPrivFromHex(t, repeatHex("05", 32)).PubKey().SerializeCompressed()
	if VerifyBitcoin(Proof{
		Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: testBtcP2WPKH(t, other), Message: message,
		Signature: testBtcToBase64(sig),
	}) {
		t.Fatal("VerifyBitcoin(P2WPKH wrong address) = true, want false")
	}
}

func TestBitcoinLegacyP2TR(t *testing.T) {
	priv := testBtcPriv(t)
	internalXonly := priv.PubKey().SerializeCompressed()[1:]
	address, _ := testBtcP2TR(t, internalXonly)
	message := testBtcMakeMessage(t, address)
	sig := testBtcSignLegacy(priv, message, true)

	if !VerifyBitcoin(Proof{
		Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: address, Message: message,
		Signature: testBtcToBase64(sig),
	}) {
		t.Fatal("VerifyBitcoin(valid P2TR legacy) = false, want true")
	}

	// Tamper -> false.
	bad := append([]byte{}, sig...)
	bad[40] ^= 0x01
	if VerifyBitcoin(Proof{
		Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: address, Message: message,
		Signature: testBtcToBase64(bad),
	}) {
		t.Fatal("VerifyBitcoin(tampered P2TR legacy) = true, want false")
	}
}

// ════════════════════════════════════════════════════════════════════════════
// BIP-322 simple
// ════════════════════════════════════════════════════════════════════════════

func TestBitcoinBip322P2WPKH(t *testing.T) {
	priv := testBtcPriv(t)
	pub := priv.PubKey().SerializeCompressed()
	address := testBtcP2WPKH(t, pub)
	message := testBtcMakeMessage(t, address)
	sig := testBtcSignBip322P2WPKH(priv, message)

	proof := Proof{
		Chain:     ChainBitcoin,
		Scheme:    SchemeBIP322,
		Address:   address,
		Message:   message,
		Signature: testBtcToBase64(sig),
		Extra:     map[string]any{"addressType": "p2wpkh"},
	}
	if !VerifyBitcoin(proof) {
		t.Fatal("VerifyBitcoin(valid BIP-322 P2WPKH) = false, want true")
	}

	// Tamper the message -> sighash changes -> false.
	if VerifyBitcoin(withMessage(proof, message+"x")) {
		t.Fatal("VerifyBitcoin(BIP-322 P2WPKH tampered message) = true, want false")
	}

	// Wrong address -> witness pubkey no longer hashes to it -> false.
	other := testBtcPrivFromHex(t, repeatHex("07", 32)).PubKey().SerializeCompressed()
	if VerifyBitcoin(withAddress(proof, testBtcP2WPKH(t, other))) {
		t.Fatal("VerifyBitcoin(BIP-322 P2WPKH wrong address) = true, want false")
	}

	// Truncated witness -> false.
	if VerifyBitcoin(withSig(proof, sig[:len(sig)-3])) {
		t.Fatal("VerifyBitcoin(BIP-322 P2WPKH truncated witness) = true, want false")
	}
}

func TestBitcoinBip322P2TR(t *testing.T) {
	priv := testBtcPriv(t)
	// Get the address first (signing over any message yields the same address).
	_, address := testBtcSignBip322P2TR(t, priv, "placeholder")
	message := testBtcMakeMessage(t, address)
	sig, _ := testBtcSignBip322P2TR(t, priv, message)

	proof := Proof{
		Chain:     ChainBitcoin,
		Scheme:    SchemeBIP322,
		Address:   address,
		Message:   message,
		Signature: testBtcToBase64(sig),
		Extra:     map[string]any{"addressType": "p2tr"},
	}
	if !VerifyBitcoin(proof) {
		t.Fatal("VerifyBitcoin(valid BIP-322 P2TR) = false, want true")
	}

	// Tamper the message -> false.
	if VerifyBitcoin(withMessage(proof, message+"z")) {
		t.Fatal("VerifyBitcoin(BIP-322 P2TR tampered message) = true, want false")
	}

	// Flip a byte in the schnorr sig -> false.
	bad := append([]byte{}, sig...)
	bad[len(bad)-1] ^= 0x01
	if VerifyBitcoin(withSig(proof, bad)) {
		t.Fatal("VerifyBitcoin(BIP-322 P2TR flipped sig) = true, want false")
	}
}

// ════════════════════════════════════════════════════════════════════════════
// malformed input fails closed
// ════════════════════════════════════════════════════════════════════════════

func TestBitcoinMalformedFailsClosed(t *testing.T) {
	priv := testBtcPriv(t)
	address := testBtcP2WPKH(t, priv.PubKey().SerializeCompressed())
	message := testBtcMakeMessage(t, address)
	base := Proof{Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: address, Message: message, Signature: ""}

	// empty signature -> false
	if VerifyBitcoin(base) {
		t.Fatal("VerifyBitcoin(empty signature) = true, want false")
	}
	// garbage base64 -> false
	if VerifyBitcoin(withSigStr(base, "!!!notbase64!!!")) {
		t.Fatal("VerifyBitcoin(garbage base64) = true, want false")
	}
	// unknown address prefix -> false
	if VerifyBitcoin(Proof{Chain: ChainBitcoin, Scheme: SchemeBIP322, Address: "3unsupportedP2SHaddress", Message: message, Signature: "AQID"}) {
		t.Fatal("VerifyBitcoin(unknown address prefix) = true, want false")
	}
	// legacy sig with out-of-range header -> false
	badHeader := make([]byte, 65)
	badHeader[0] = 99
	if VerifyBitcoin(withSig(base, badHeader)) {
		t.Fatal("VerifyBitcoin(out-of-range header) = true, want false")
	}
}

func TestBitcoinDoesNotPanicOnGarbage(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyBitcoin panicked on garbage: %v", r)
		}
	}()
	garbage := Proof{
		Chain:     ChainBitcoin,
		Scheme:    SchemeBIP322,
		Address:   "bc1pgarbage",
		Message:   "not a siwx message",
		Signature: "AQIDBA==",
		Extra:     map[string]any{"addressType": "p2tr"},
	}
	if VerifyBitcoin(garbage) {
		t.Fatal("VerifyBitcoin(garbage) = true, want false")
	}
}

// Sanity: the verifier's address derivations match the independent helpers for a
// freshly used key (guards against silent drift in either direction).
func TestBitcoinDeriveMatchesHelpers(t *testing.T) {
	priv := testBtcPriv(t)
	pubC := priv.PubKey().SerializeCompressed()

	if got, want := btcDeriveP2PKH(pubC), testBtcP2PKH(t, pubC); got != want {
		t.Fatalf("btcDeriveP2PKH = %q, helper = %q", got, want)
	}
	gotW, ok := btcDeriveP2WPKH(pubC)
	if !ok || gotW != testBtcP2WPKH(t, pubC) {
		t.Fatalf("btcDeriveP2WPKH = %q,%v; helper = %q", gotW, ok, testBtcP2WPKH(t, pubC))
	}
	internalXonly := pubC[1:]
	wantAddr, _ := testBtcP2TR(t, internalXonly)
	gotT, ok := btcDeriveP2TR(internalXonly)
	if !ok || gotT != wantAddr {
		t.Fatalf("btcDeriveP2TR = %q,%v; helper = %q", gotT, ok, wantAddr)
	}
}

// ── small Proof mutators (avoid struct-literal churn) ────────────────────────

func withSig(p Proof, sig []byte) Proof {
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return p
}
func withSigStr(p Proof, s string) Proof  { p.Signature = s; return p }
func withMessage(p Proof, m string) Proof { p.Message = m; return p }
func withAddress(p Proof, a string) Proof { p.Address = a; return p }

func repeatHex(b string, n int) string {
	out := make([]byte, 0, len(b)*n)
	for i := 0; i < n; i++ {
		out = append(out, b...)
	}
	return string(out)
}
