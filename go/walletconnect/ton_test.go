package walletconnect

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// TON ton_proof verifier tests. Mirror src/__tests__/ton.test.ts.
//
// The wallet-side ton_proof digest is reconstructed INDEPENDENTLY here (it does
// not call tonBuildMessage / tonProofDigest), so the "accepts a valid proof"
// round-trip genuinely cross-checks the verifier: if the two ever drift, this
// test fails — which is the whole point. All helpers below are local (suffixed
// or method-scoped) so they never collide with the parallel XRP/Bitcoin test
// files in this flat package.

// tonTestEnvelope is the wallet-side ProofEnvelope (mirrors the TS interface).
type tonTestEnvelope struct {
	timestamp      int64
	domain         string
	payload        string
	workchain      int32
	addressHashHex string
}

// tonTestDigest reproduces the TON Connect ton_proof signing algorithm
// (the wallet side), byte-for-byte with src/ton/verify.ts. Kept independent of
// the verifier internals on purpose.
func tonTestDigest(t *testing.T, env tonTestEnvelope) []byte {
	t.Helper()
	addressHash, err := hex.DecodeString(strings.TrimPrefix(env.addressHashHex, "0x"))
	if err != nil {
		t.Fatalf("tonTestDigest: bad addressHashHex: %v", err)
	}

	var wc [4]byte
	binary.BigEndian.PutUint32(wc[:], uint32(env.workchain)) // big-endian, signed

	domainBytes := []byte(env.domain)
	var dlen [4]byte
	binary.LittleEndian.PutUint32(dlen[:], uint32(len(domainBytes))) // little-endian

	var ts [8]byte
	binary.LittleEndian.PutUint64(ts[:], uint64(env.timestamp)) // little-endian

	var message []byte
	message = append(message, []byte("ton-proof-item-v2/")...)
	message = append(message, wc[:]...)
	message = append(message, addressHash...)
	message = append(message, dlen[:]...)
	message = append(message, domainBytes...)
	message = append(message, ts[:]...)
	message = append(message, []byte(env.payload)...)

	inner := sha256.Sum256(message)
	var full []byte
	full = append(full, 0xff, 0xff)
	full = append(full, []byte("ton-connect")...)
	full = append(full, inner[:]...)
	digest := sha256.Sum256(full)
	return digest[:]
}

// tonMinted bundles a freshly-minted, self-consistent TON proof.
type tonMinted struct {
	proof Proof
	env   tonTestEnvelope
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

type tonMintOpts struct {
	workchain int32
	domain    string
	nowMs     int64
}

// tonMintProof mints a fresh, self-consistent TON proof: random ed25519 key, a
// CAIP-122 message whose Nonce equals the ton_proof payload, and a real
// signature over the reconstructed digest. Mirrors the TS mintProof helper,
// using the package's existing newChallenge/BuildSiwxMessage test helpers.
func tonMintProof(t *testing.T, o tonMintOpts) tonMinted {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	// A TON address-hash (account state-init hash). For the verifier it is just
	// 32 opaque bytes; use a deterministic-but-arbitrary value (sha256 of pub).
	ah := sha256.Sum256(pub)
	addressHashHex := hex.EncodeToString(ah[:])

	workchain := o.workchain
	domain := o.domain
	if domain == "" {
		domain = "hanzo.id"
	}
	nowMs := o.nowMs
	if nowMs == 0 {
		nowMs = 1_700_000_000_000
	}
	timestamp := nowMs / 1000

	// Server mints the nonce; the connector reuses it as the ton_proof payload.
	// The package's newChallenge takes the nonce explicitly, so we set it here
	// and reuse the same value as the payload — exactly the binding the verifier
	// enforces (parsed.Nonce == extra.payload).
	payload := "siwx-nonce-deadbeefcafe"
	challenge := newChallenge(challengeOpts{
		domain: domain,
		uri:    "https://" + domain + "/login",
		nonce:  payload,
		nowMs:  nowMs,
	})

	// The on-chain "address" used for binding: raw TON address form
	// "<workchain>:<addressHashHex>", which must equal the SIWx address line.
	address := itoaInt32(workchain) + ":" + addressHashHex

	message := mustBuild(t, BuildParams{Challenge: challenge, Address: address, Chain: ChainTON})

	env := tonTestEnvelope{
		timestamp:      timestamp,
		domain:         domain,
		payload:        payload,
		workchain:      workchain,
		addressHashHex: addressHashHex,
	}
	digest := tonTestDigest(t, env)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest))

	proof := Proof{
		Chain:     ChainTON,
		Scheme:    SchemeTonProof,
		Address:   address,
		PublicKey: hex.EncodeToString(pub),
		Message:   message,
		Signature: signature,
		Extra:     tonEnvToExtra(env),
	}
	return tonMinted{proof: proof, env: env, priv: priv, pub: pub}
}

// tonEnvToExtra renders the wallet-side envelope into the map[string]any shape
// the verifier receives. Critically, the numeric fields are float64 — exactly
// how JSON decoding delivers them — so the verifier's float64->int narrowing is
// exercised on the happy path, not just the error paths.
func tonEnvToExtra(env tonTestEnvelope) map[string]any {
	return map[string]any{
		"timestamp":      float64(env.timestamp),
		"domain":         env.domain,
		"payload":        env.payload,
		"workchain":      float64(env.workchain),
		"addressHashHex": env.addressHashHex,
	}
}

// itoaInt32 formats a signed int32 in base 10 (handles the -1 masterchain case).
func itoaInt32(v int32) string {
	if v < 0 {
		return "-" + itoaInt32(-v)
	}
	if v < 10 {
		return string(rune('0' + v))
	}
	return itoaInt32(v/10) + string(rune('0'+v%10))
}

// cloneExtra deep-copies the proof's Extra map so a test mutation does not leak.
func cloneExtra(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func TestTonAcceptsValidProof(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	if !VerifyTon(m.proof) {
		t.Fatal("VerifyTon = false, want true for a valid proof")
	}
}

func TestTonAcceptsMasterchainWorkchain(t *testing.T) {
	// Exercises signed int32BE encoding: -1 must serialize as 0xFFFFFFFF on both
	// the signing and verifying sides.
	m := tonMintProof(t, tonMintOpts{workchain: -1})
	if !VerifyTon(m.proof) {
		t.Fatal("VerifyTon = false, want true for workchain=-1")
	}
}

func TestTonRejectsTamperedTimestamp(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	bad := m.proof
	bad.Extra = cloneExtra(m.proof.Extra)
	// Mutate only the envelope timestamp (still a valid integer, so the envelope
	// parses) -> the signed message no longer matches -> crypto rejects.
	bad.Extra["timestamp"] = float64(m.env.timestamp + 1)
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for tampered timestamp")
	}
}

func TestTonRejectsTamperedDomain(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	bad := m.proof
	bad.Extra = cloneExtra(m.proof.Extra)
	bad.Extra["domain"] = "evil.com"
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for tampered domain")
	}
}

func TestTonRejectsTamperedPayload(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	// Mutate BOTH the SIWx nonce and the envelope payload so the binding check
	// passes and we isolate the cryptographic rejection (the signature was made
	// over the old payload).
	tampered := m.env.payload + "X"
	bad := m.proof
	bad.Message = replaceNonceLine(m.proof.Message, tampered)
	bad.Extra = cloneExtra(m.proof.Extra)
	bad.Extra["payload"] = tampered
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for tampered payload")
	}
}

func TestTonRejectsWrongPublicKey(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	bad := m.proof
	bad.PublicKey = hex.EncodeToString(otherPub)
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for wrong public key")
	}
}

func TestTonRejectsNoncePayloadMismatch(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	// Envelope payload no longer equals the SIWx Nonce -> binding rejects it
	// even though the signature (over the old payload) is untouched.
	bad := m.proof
	bad.Extra = cloneExtra(m.proof.Extra)
	bad.Extra["payload"] = "a-different-nonce"
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for nonce/payload mismatch")
	}
}

func TestTonRejectsAddressMismatch(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	bad := m.proof
	bad.Address = "0:deadbeef"
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for address not matching SIWx")
	}
}

func TestTonRejectsMalformedSignatureLength(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	bad := m.proof
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 63))
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for 63-byte signature")
	}
}

func TestTonRejectsMalformedPublicKeyLength(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	bad := m.proof
	bad.PublicKey = hex.EncodeToString(make([]byte, 31))
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for 31-byte public key")
	}
}

func TestTonRejectsMalformedAddressHashLength(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	bad := m.proof
	bad.Extra = cloneExtra(m.proof.Extra)
	bad.Extra["addressHashHex"] = "dead" // 2 bytes, not 32
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for short address hash")
	}
}

func TestTonFailsClosedOnMissingEnvelope(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	bad := m.proof
	bad.Extra = nil
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for missing envelope")
	}
}

func TestTonFailsClosedOnMissingPublicKey(t *testing.T) {
	m := tonMintProof(t, tonMintOpts{})
	bad := m.proof
	bad.PublicKey = ""
	if VerifyTon(bad) {
		t.Fatal("VerifyTon = true, want false for missing public key")
	}
}

func TestTonDoesNotPanicOnGarbage(t *testing.T) {
	// Numeric fields are deliberately the wrong dynamic types (string, nil,
	// non-integer float) to exercise the float64-narrowing guards. JSON would
	// never produce an int for workchain=0.5, so the float64(0.5) here matches
	// the TS `workchain: 0.5` case exactly.
	garbage := Proof{
		Chain:     ChainTON,
		Scheme:    SchemeTonProof,
		Address:   "x",
		PublicKey: "nothex",
		Message:   "not a siwx message",
		Signature: "!!!!",
		Extra: map[string]any{
			"timestamp":      "soon",
			"domain":         float64(1),
			"payload":        nil,
			"workchain":      0.5,
			"addressHashHex": float64(7),
		},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyTon panicked on garbage input: %v", r)
		}
	}()
	if VerifyTon(garbage) {
		t.Fatal("VerifyTon = true, want false for garbage input")
	}
}

// replaceNonceLine rewrites the "Nonce: ..." line of a CAIP-122 message with a
// new nonce value (the Go analog of the TS regexp replace).
func replaceNonceLine(message, newNonce string) string {
	lines := strings.Split(message, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "Nonce: ") {
			lines[i] = "Nonce: " + newNonce
		}
	}
	return strings.Join(lines, "\n")
}
