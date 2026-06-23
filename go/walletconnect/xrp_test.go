package walletconnect

// Mirrors src/__tests__/xrp.test.ts. Every test reproduces the XRPL signing +
// r-address derivation INDEPENDENTLY of the verifier (no shared internals), so
// if the two ever drift the round-trip "accepts a valid proof" test fails —
// the whole point of mirroring rather than importing verifier internals.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // XRPL AccountID uses RIPEMD-160.
)

// --- Independent wallet-side spec implementation. ---

const testXrpAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

func testXrpSha256(d []byte) []byte {
	s := sha256.Sum256(d)
	return s[:]
}

// testXrpBase58Check: independent XRPL base58check (version-prefixed payload in).
func testXrpBase58Check(payload []byte) string {
	checksum := testXrpSha256(testXrpSha256(payload))[:4]
	full := append(append([]byte{}, payload...), checksum...)

	acc := new(big.Int).SetBytes(full)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for acc.Sign() > 0 {
		acc.DivMod(acc, radix, mod)
		out = append(out, testXrpAlphabet[mod.Int64()])
	}
	for i := 0; i < len(full) && full[i] == 0; i++ {
		out = append(out, testXrpAlphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// testXrpRAddress: r-address from a full 33-byte XRPL public key.
func testXrpRAddress(pubkey33 []byte) string {
	rip := ripemd160.New()
	rip.Write(testXrpSha256(pubkey33))
	accountID := rip.Sum(nil)
	return testXrpBase58Check(append([]byte{0x00}, accountID...))
}

func testXrpChallenge(now string) LoginChallenge {
	return LoginChallenge{
		Domain:   "hanzo.id",
		URI:      "https://hanzo.id/login",
		Nonce:    "0123456789abcdef0123456789abcdef",
		IssuedAt: now,
	}
}

func testXrpBuildMessage(t *testing.T, address string) string {
	t.Helper()
	msg, err := BuildSiwxMessage(BuildParams{
		Challenge: testXrpChallenge("2026-01-01T00:00:00.000Z"),
		Address:   address,
		Chain:     ChainXRP,
	})
	if err != nil {
		t.Fatalf("BuildSiwxMessage: %v", err)
	}
	return msg
}

// mintEd25519: key -> r-address -> SIWx -> raw ed25519 sig. Mirrors the TS
// mintEd25519.
func testXrpMintEd25519(t *testing.T) Proof {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	// XRPL ed25519 public key = 0xED || 32-byte Edwards key.
	pubkey33 := append([]byte{0xed}, pub...)
	address := testXrpRAddress(pubkey33)
	message := testXrpBuildMessage(t, address)

	// ed25519-xrpl signs the raw UTF-8 message bytes.
	sig := ed25519.Sign(priv, []byte(message))

	return Proof{
		Chain:     ChainXRP,
		Scheme:    SchemeEd25519XRPL,
		Address:   address,
		PublicKey: hex.EncodeToString(pubkey33),
		Message:   message,
		Signature: hex.EncodeToString(sig),
	}
}

// mintSecp256k1: key -> r-address -> SIWx -> DER sig over sha512half. Mirrors
// the TS mintSecp256k1. decred's ecdsa.Sign is RFC-6979 deterministic and
// produces low-S canonical signatures, matching the TS { lowS: true } wallet
// side; the verifier accepts any-S ({ lowS: false }).
func testXrpMintSecp256k1(t *testing.T) Proof {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("secp256k1 keygen: %v", err)
	}
	pubkey33 := priv.PubKey().SerializeCompressed() // 0x02/0x03 || 32
	address := testXrpRAddress(pubkey33)
	message := testXrpBuildMessage(t, address)

	// secp256k1-xrpl signs the sha512half of the message, DER-encoded.
	digest := xrpSha512Half([]byte(message))
	sig := ecdsa.Sign(priv, digest)
	der := sig.Serialize()

	return Proof{
		Chain:     ChainXRP,
		Scheme:    SchemeSecp256k1XRPL,
		Address:   address,
		PublicKey: hex.EncodeToString(pubkey33),
		Message:   message,
		Signature: hex.EncodeToString(der),
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// --- KAT: xrpl.org Address Encoding worked example. ---

func TestXrpBase58CheckKnownAnswer(t *testing.T) {
	// From https://xrpl.org/addresses.html:
	//   AccountID = BA8E78626EE42C41B46D46C3048DF3A1C3C87072
	//   r-address = rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN
	accountID := mustHex(t, "BA8E78626EE42C41B46D46C3048DF3A1C3C87072")
	got := xrpBase58Check(append([]byte{0x00}, accountID...))
	const want = "rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN"
	if got != want {
		t.Fatalf("xrpBase58Check = %q, want %q", got, want)
	}
	// The independent test encoder must agree with the verifier's encoder.
	if alt := testXrpBase58Check(append([]byte{0x00}, accountID...)); alt != want {
		t.Fatalf("test encoder = %q, want %q", alt, want)
	}
}

// --- ed25519-xrpl ---

func TestXrpEd25519AcceptsValidProof(t *testing.T) {
	proof := testXrpMintEd25519(t)
	if !VerifyXrp(proof) {
		t.Fatal("VerifyXrp(valid ed25519 proof) = false, want true")
	}
}

func TestXrpEd25519RejectsTamperedMessage(t *testing.T) {
	proof := testXrpMintEd25519(t)
	proof.Message += " "
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(tampered message) = true, want false")
	}
}

func TestXrpEd25519RejectsFlippedSignatureBit(t *testing.T) {
	proof := testXrpMintEd25519(t)
	sig := mustHex(t, proof.Signature)
	sig[0] ^= 0x01
	proof.Signature = hex.EncodeToString(sig)
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(flipped sig bit) = true, want false")
	}
}

func TestXrpEd25519RejectsWrongAddress(t *testing.T) {
	proof := testXrpMintEd25519(t)
	other := testXrpMintEd25519(t)
	proof.Address = other.Address
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(wrong address) = true, want false")
	}
}

func TestXrpEd25519RejectsMismatchedPublicKey(t *testing.T) {
	proof := testXrpMintEd25519(t)
	other := testXrpMintEd25519(t)
	// Valid 0xED-prefixed key but not the signer -> sig verify fails.
	proof.PublicKey = other.PublicKey
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(mismatched pubkey) = true, want false")
	}
}

func TestXrpEd25519RejectsMissingEdPrefix(t *testing.T) {
	proof := testXrpMintEd25519(t)
	b := mustHex(t, proof.PublicKey)
	b[0] = 0xee // wrong family tag
	proof.PublicKey = hex.EncodeToString(b)
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(wrong family tag) = true, want false")
	}
}

func TestXrpEd25519FailsClosedOnMissingPublicKey(t *testing.T) {
	proof := testXrpMintEd25519(t)
	proof.PublicKey = ""
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(missing pubkey) = true, want false")
	}
}

// --- secp256k1-xrpl ---

func TestXrpSecp256k1AcceptsValidProof(t *testing.T) {
	proof := testXrpMintSecp256k1(t)
	if !VerifyXrp(proof) {
		t.Fatal("VerifyXrp(valid secp256k1 proof) = false, want true")
	}
}

func TestXrpSecp256k1RejectsTamperedMessage(t *testing.T) {
	proof := testXrpMintSecp256k1(t)
	proof.Message += " "
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(tampered message) = true, want false")
	}
}

func TestXrpSecp256k1RejectsCorruptedDER(t *testing.T) {
	proof := testXrpMintSecp256k1(t)
	der := mustHex(t, proof.Signature)
	der[len(der)-1] ^= 0x01 // mangle last byte of s
	proof.Signature = hex.EncodeToString(der)
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(corrupted DER) = true, want false")
	}
}

func TestXrpSecp256k1RejectsWrongAddress(t *testing.T) {
	proof := testXrpMintSecp256k1(t)
	other := testXrpMintSecp256k1(t)
	proof.Address = other.Address
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(wrong address) = true, want false")
	}
}

func TestXrpSecp256k1RejectsMismatchedPublicKey(t *testing.T) {
	proof := testXrpMintSecp256k1(t)
	other := testXrpMintSecp256k1(t)
	proof.PublicKey = other.PublicKey
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(mismatched pubkey) = true, want false")
	}
}

func TestXrpSecp256k1RejectsEdTaggedKey(t *testing.T) {
	proof := testXrpMintSecp256k1(t)
	b := mustHex(t, proof.PublicKey)
	b[0] = 0xed // not a valid compressed-point tag
	proof.PublicKey = hex.EncodeToString(b)
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(ed-tagged key under secp scheme) = true, want false")
	}
}

func TestXrpSecp256k1FailsClosedOnMissingPublicKey(t *testing.T) {
	proof := testXrpMintSecp256k1(t)
	proof.PublicKey = ""
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(missing pubkey) = true, want false")
	}
}

// --- fail-closed hardening ---

func TestXrpRejectsUnknownScheme(t *testing.T) {
	proof := testXrpMintEd25519(t)
	proof.Scheme = SchemeEd25519 // not an XRPL scheme
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(unknown scheme) = true, want false")
	}
}

func TestXrpDoesNotPanicOnGarbage(t *testing.T) {
	garbage := Proof{
		Chain:     ChainXRP,
		Scheme:    SchemeEd25519XRPL,
		Address:   "x",
		PublicKey: "nothex",
		Message:   "not a siwx message",
		Signature: "!!!!",
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyXrp panicked on garbage: %v", r)
		}
	}()
	if VerifyXrp(garbage) {
		t.Fatal("VerifyXrp(garbage) = true, want false")
	}
}

func TestXrpRejectsWrongLengthPublicKey(t *testing.T) {
	proof := testXrpMintEd25519(t)
	proof.PublicKey = hex.EncodeToString(make([]byte, 31))
	if VerifyXrp(proof) {
		t.Fatal("VerifyXrp(31-byte pubkey) = true, want false")
	}
}

// Sanity: the verifier's derivation matches the independent test derivation for
// a freshly minted key (guards against silent drift in either direction).
func TestXrpDeriveAddressMatchesTestHelper(t *testing.T) {
	proof := testXrpMintEd25519(t)
	pubkey33 := mustHex(t, proof.PublicKey)
	if got, want := xrpDeriveAddress(pubkey33), testXrpRAddress(pubkey33); got != want {
		t.Fatalf("xrpDeriveAddress = %q, test helper = %q", got, want)
	}
	if !strings.HasPrefix(proof.Address, "r") {
		t.Fatalf("derived address %q does not start with 'r'", proof.Address)
	}
}
