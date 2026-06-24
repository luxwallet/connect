package walletconnect

// Fuzz / property tests for the SIWx verify core (Go port).
//
// Two invariants every verifier and the dispatcher must satisfy under ANY input:
//
//	(A) NEVER panics — a verifier returns a bool (or a Result), never an
//	    out-of-band panic. A panic on attacker input is a DoS and breaks
//	    fail-closed semantics. (In Go a stack overflow is FATAL and not even
//	    recover()-able, so the recursive CBOR decoder is explicitly depth-bounded.)
//	(B) NEVER returns OK for a non-valid proof — random/mutated bytes must not
//	    forge a login. The positive direction (real signatures verify) is covered
//	    by the per-chain *_test.go suites and the cross-language KATs.
//
// Two layers:
//   - Go native fuzzing (FuzzVerifyProof, FuzzParseSiwx, FuzzCborDecode): run
//     with `go test -fuzz=Fuzz...`; in plain `go test` they replay the seed
//     corpus. These assert no panic + no spurious OK.
//   - Deterministic property tests (TestFuzzProperty*): a seeded PRNG drives
//     thousands of malformed proofs through every verifier and both dispatch
//     entry points, plus a hand-built adversarial corpus, in ordinary `go test`.

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"testing"
)

// ── deterministic PRNG (mulberry32, matching the TS fuzz seed style) ──────────

type prng struct{ a uint32 }

func newPRNG(seed uint32) *prng { return &prng{a: seed} }

func (p *prng) next() uint32 {
	p.a += 0x6d2b79f5
	t := p.a
	t = (t ^ (t >> 15)) * (t | 1)
	t ^= t + (t^(t>>7))*(t|61)
	return t ^ (t >> 14)
}

func (p *prng) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(p.next() % uint32(n))
}

// randEncoded produces a random byte string in one of several attacker
// encodings (hex with/without 0x, base64, raw junk, empty, occasionally huge).
func (p *prng) randEncoded() string {
	n := p.intn(200)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(p.intn(256))
	}
	switch p.intn(6) {
	case 0:
		return "0x" + hex.EncodeToString(b)
	case 1:
		return hex.EncodeToString(b)
	case 2:
		return base64.StdEncoding.EncodeToString(b)
	case 3:
		out := make([]byte, n)
		for i := range out {
			out[i] = byte(33 + (p.intn(90)))
		}
		return string(out)
	case 4:
		return ""
	default:
		if p.intn(4) == 0 {
			return string(make([]byte, 200_000)) // oversized -> DoS guard
		}
		return hex.EncodeToString(b)
	}
}

var allSchemes = []SignatureScheme{
	SchemeSecp256k1EIP191, SchemeEd25519, SchemeBIP322, SchemeTonProof,
	SchemeSecp256k1XRPL, SchemeEd25519XRPL, SchemeSr25519, SchemeEd25519Substr,
	SchemeEcdsaSubstr, SchemeEd25519Cardano,
}

var allChains = []Chain{
	ChainEVM, ChainSolana, ChainBitcoin, ChainTON, ChainXRP, ChainPolkadot, ChainCardano,
}

// randProof builds a fully-random proof: every field attacker-chosen, including
// junk Extra (NaN/Inf/overflow numbers, oversized strings).
func (p *prng) randProof() Proof {
	var extra map[string]any
	switch p.intn(5) {
	case 0:
		extra = nil
	case 1:
		extra = map[string]any{}
	case 2:
		extra = map[string]any{"addressType": p.randEncoded()}
	case 3:
		tsChoices := []float64{math.NaN(), math.Inf(1), -1, 1.5, math.Pow(2, 60), float64(p.intn(1e9))}
		wcChoices := []float64{math.NaN(), math.Inf(-1), 1e40, 0, -1}
		extra = map[string]any{
			"timestamp":      tsChoices[p.intn(len(tsChoices))],
			"workchain":      wcChoices[p.intn(len(wcChoices))],
			"domain":         p.randEncoded(),
			"payload":        p.randEncoded(),
			"addressHashHex": p.randEncoded(),
		}
	default:
		extra = map[string]any{"coseKey": p.randEncoded()}
	}
	var pk string
	if p.intn(2) == 1 {
		pk = p.randEncoded()
	}
	return Proof{
		Chain:     allChains[p.intn(len(allChains))],
		Scheme:    allSchemes[p.intn(len(allSchemes))],
		Address:   p.randEncoded(),
		PublicKey: pk,
		Message:   p.randEncoded(),
		Signature: p.randEncoded(),
		Extra:     extra,
	}
}

// callVerifier runs the scheme's verifier directly and reports (panicked, ok).
// It exists so the property test can assert (A) no-panic per verifier as well as
// (B) no-spurious-OK. Polkadot/Cardano/TON re-check their scheme internally.
func callVerifier(p Proof) (panicked, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	switch p.Scheme {
	case SchemeSecp256k1EIP191:
		ok = VerifyEVM(p.Message, p.Signature, p.Address)
	case SchemeEd25519:
		ok = VerifySolana(p.Message, p.Signature, p.Address)
	case SchemeTonProof:
		ok = VerifyTon(p)
	case SchemeBIP322:
		ok = VerifyBitcoin(p)
	case SchemeSecp256k1XRPL, SchemeEd25519XRPL:
		ok = VerifyXrp(p)
	case SchemeSr25519, SchemeEd25519Substr, SchemeEcdsaSubstr:
		ok = VerifyPolkadot(p)
	case SchemeEd25519Cardano:
		ok = VerifyCardano(p)
	}
	return panicked, ok
}

// ── (A)+(B): property fuzz of every verifier ──────────────────────────────────

func TestFuzzPropertyVerifiers(t *testing.T) {
	p := newPRNG(12345)
	const iters = 20000
	for i := 0; i < iters; i++ {
		proof := p.randProof()
		panicked, ok := callVerifier(proof)
		if panicked {
			t.Fatalf("verifier panicked on input #%d: %+v", i, proof)
		}
		if ok {
			t.Fatalf("verifier returned OK for random (non-valid) proof #%d: %+v", i, proof)
		}
	}
}

// ── (A)+(B): property fuzz of the dispatcher ──────────────────────────────────

func TestFuzzPropertyDispatcher(t *testing.T) {
	p := newPRNG(67890)
	const iters = 20000
	ranCrypto := 0
	for i := 0; i < iters; i++ {
		proof := p.randProof()
		expected := Expectation{Domain: p.randEncoded(), Nonce: p.randEncoded()}
		res := func() (r Result) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("VerifyProof panicked on input #%d: %+v", i, proof)
				}
			}()
			return VerifyProof(proof, expected)
		}()
		if res.OK {
			t.Fatalf("VerifyProof returned OK for random proof #%d: %+v", i, proof)
		}
		if res.Reason == "" {
			t.Fatalf("VerifyProof returned no reason for rejected proof #%d", i)
		}
		if res.Reason == ReasonBadSignature {
			ranCrypto++
		}
	}
	// Sanity: the fuzzer actually drove inputs past the gate into the crypto
	// layer (so (B) is not trivially satisfied by everything failing at the gate).
	if ranCrypto == 0 {
		t.Fatal("fuzzer never reached the crypto layer; property test is vacuous")
	}
}

// ── cross-scheme confusion: deterministic, exhaustive ────────────────────────

func TestCrossSchemeConfusion(t *testing.T) {
	expected := Expectation{Domain: "hanzo.id", Nonce: "abc12345"}
	for _, chain := range allChains {
		for _, scheme := range allSchemes {
			proof := Proof{
				Chain:     chain,
				Scheme:    scheme,
				Address:   "0x" + repeat("0", 40),
				PublicKey: repeat("00", 33),
				Message:   "whatever",
				Signature: "0x" + repeat("0", 130),
			}
			res := VerifyProof(proof, expected)
			// A mismatched (chain, scheme) MUST be rejected as unsupported-scheme
			// by the gate, before any crypto. A legitimate pair passes the gate
			// and fails later — but never with OK=true.
			if !chainAllowsScheme(chain, scheme) {
				if res.Reason != ReasonUnsupportedScheme {
					t.Errorf("(%s,%s): expected unsupported-scheme, got %s", chain, scheme, res.Reason)
				}
			}
			if res.OK {
				t.Errorf("(%s,%s): forged OK", chain, scheme)
			}
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// ── adversarial corpus: specific known-nasty vectors ─────────────────────────

func TestAdversarialCorpus(t *testing.T) {
	good := Expectation{Domain: "hanzo.id", Nonce: "abc12345"}
	cases := []struct {
		name  string
		proof Proof
	}{
		{"empty everything", Proof{Chain: ChainEVM, Scheme: SchemeSecp256k1EIP191}},
		{"oversized message", Proof{Chain: ChainEVM, Scheme: SchemeSecp256k1EIP191, Address: "0x" + repeat("0", 40), Message: repeat("A", 500000), Signature: "0x" + repeat("0", 130)}},
		{"oversized signature", Proof{Chain: ChainSolana, Scheme: SchemeEd25519, Address: "So11111111111111111111111111111111111111112", Message: "m", Signature: repeat("A", 500000)}},
		{"oversized publicKey", Proof{Chain: ChainXRP, Scheme: SchemeEd25519XRPL, Address: "rXYZ", PublicKey: "ed" + repeat("a", 500000), Message: "m", Signature: "00"}},
		{"cross-scheme evm+ed25519", Proof{Chain: ChainEVM, Scheme: SchemeEd25519, Address: "0x" + repeat("1", 40), Message: "m", Signature: "AAAA"}},
		{"cross-scheme solana+eip191", Proof{Chain: ChainSolana, Scheme: SchemeSecp256k1EIP191, Address: "So11111111111111111111111111111111111111112", Message: "m", Signature: "0x" + repeat("0", 130)}},
		{"unknown scheme", Proof{Chain: ChainEVM, Scheme: "totally-made-up", Address: "0x" + repeat("0", 40), Message: "m", Signature: "0x00"}},
		{"non-hex evm sig", Proof{Chain: ChainEVM, Scheme: SchemeSecp256k1EIP191, Address: "0x" + repeat("0", 40), Message: "m", Signature: "0xZZZZnothex"}},
		{"evm sig wrong length", Proof{Chain: ChainEVM, Scheme: SchemeSecp256k1EIP191, Address: "0x" + repeat("0", 40), Message: "m", Signature: "0x" + repeat("0", 128)}},
		{"ton timestamp NaN", Proof{Chain: ChainTON, Scheme: SchemeTonProof, Address: "EQ", PublicKey: repeat("ed", 16), Message: "m", Signature: "AA==", Extra: map[string]any{"timestamp": math.NaN(), "workchain": float64(0), "domain": "d", "payload": "abc12345", "addressHashHex": repeat("00", 32)}}},
		{"ton workchain overflow", Proof{Chain: ChainTON, Scheme: SchemeTonProof, Address: "EQ", PublicKey: repeat("00", 32), Message: "m", Signature: "AA==", Extra: map[string]any{"timestamp": float64(1), "workchain": 1e40, "domain": "d", "payload": "abc12345", "addressHashHex": repeat("00", 32)}}},
		{"cardano garbage cbor", Proof{Chain: ChainCardano, Scheme: SchemeEd25519Cardano, Address: "addr1xyz", PublicKey: repeat("00", 32), Message: "m", Signature: repeat("deadbeef", 10)}},
		{"cardano malformed bech32", Proof{Chain: ChainCardano, Scheme: SchemeEd25519Cardano, Address: "addr1!!!notbech32", PublicKey: repeat("00", 32), Message: "m", Signature: repeat("00", 80)}},
		{"polkadot malformed ss58", Proof{Chain: ChainPolkadot, Scheme: SchemeSr25519, Address: "!!!not-ss58!!!", PublicKey: repeat("00", 32), Message: "m", Signature: repeat("00", 64)}},
		{"cardano deep-cbor sig", Proof{Chain: ChainCardano, Scheme: SchemeEd25519Cardano, Address: "addr1xyz", PublicKey: repeat("00", 32), Message: "m", Signature: repeat("81", 1000)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := func() (r Result) {
				defer func() {
					if rec := recover(); rec != nil {
						t.Fatalf("panicked: %v", rec)
					}
				}()
				return VerifyProof(c.proof, good)
			}()
			if res.OK {
				t.Fatalf("forged OK on %q", c.name)
			}
			if res.Reason == "" {
				t.Fatalf("no reason on %q", c.name)
			}
		})
	}
}

// ── Go native fuzzers (run: go test -fuzz=FuzzVerifyProof) ────────────────────

// FuzzVerifyProof drives raw bytes into every field of a Proof and asserts the
// dispatcher never panics and never forges OK. Seed corpus covers each chain.
func FuzzVerifyProof(f *testing.F) {
	f.Add("evm", "secp256k1-eip191", "0x0000000000000000000000000000000000000000", "", "msg", "0x00")
	f.Add("solana", "ed25519", "So11111111111111111111111111111111111111112", "", "msg", "AAAA")
	f.Add("cardano", "ed25519-cardano", "addr1xyz", "00", "msg", "81818181")
	f.Add("ton", "ton-proof", "EQ", "ed", "msg", "AA==")
	f.Add("bitcoin", "bip322", "bc1qxyz", "", "msg", "AA==")
	f.Fuzz(func(t *testing.T, chain, scheme, addr, pub, msg, sig string) {
		proof := Proof{
			Chain: Chain(chain), Scheme: SignatureScheme(scheme),
			Address: addr, PublicKey: pub, Message: msg, Signature: sig,
			Extra: map[string]any{"timestamp": float64(1), "workchain": float64(0), "domain": "d", "payload": "p", "addressHashHex": "00", "coseKey": pub, "addressType": "p2wpkh"},
		}
		res := VerifyProof(proof, Expectation{Domain: "hanzo.id", Nonce: "abc12345"})
		if res.OK {
			t.Fatalf("forged OK: %+v", proof)
		}
	})
}

// FuzzParseSiwx asserts the CAIP-122 parser never panics on arbitrary bytes.
func FuzzParseSiwx(f *testing.F) {
	f.Add("hanzo.id wants you to sign in with your Ethereum account:\n0xabc\n\nURI: x\nNonce: n\nIssued At: t")
	f.Add("\n\n\n\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, msg string) {
		_, _ = ParseSiwxMessage(msg) // must not panic; error is fine
	})
}

// FuzzCborDecode asserts the CBOR decoder never panics (incl. deep nesting).
func FuzzCborDecode(f *testing.F) {
	f.Add([]byte{0x84, 0x6a, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1'})
	f.Add([]byte{0x81, 0x81, 0x81, 0x81, 0x81})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, buf []byte) {
		_, _ = cborDecode(buf) // must not panic; ok=false is fine
	})
}
