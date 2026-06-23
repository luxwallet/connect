package walletconnect

// Inline bech32 (BIP-173) / bech32m (BIP-350) segwit address encoding and
// Base58Check (Bitcoin alphabet) — no deps. Encode-only: we derive an address
// from a recovered/known pubkey and compare it byte-for-byte against the
// claimed proof.Address string. Mirrors src/bitcoin/bech32.ts and
// src/bitcoin/base58check.ts.
//
// Every identifier here is btc-prefixed: TON and XRP share this flat package.

import "crypto/sha256"

const btcCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

const (
	btcBech32Const  = 1
	btcBech32mConst = 0x2bc830a3
)

// btcPolymod is the bech32 checksum step. Mirrors the TS polymod.
func btcPolymod(values []int) uint32 {
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// btcHrpExpand mirrors the TS hrpExpand.
func btcHrpExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])&31)
	}
	return out
}

// btcConvert8to5 converts an 8-bit byte array to 5-bit groups (pad=true).
// Mirrors the TS convert8to5. Returns nil on invalid input.
func btcConvert8to5(data []byte) []int {
	var acc uint32
	var bits int
	out := make([]int, 0, len(data)*8/5+1)
	const maxv = 31
	for _, value := range data {
		// value is a byte so 0..255; value>>8 is always 0 — the TS guard is
		// vacuous here, kept implicitly.
		acc = ((acc << 8) | uint32(value)) & 0xffffffff
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, int((acc>>uint(bits))&maxv))
		}
	}
	if bits > 0 {
		out = append(out, int((acc<<uint(5-bits))&maxv))
	}
	return out
}

// btcConvert5to8 converts 5-bit groups to 8-bit bytes (pad=false), strict per
// BIP-173. Mirrors the TS convert5to8 (used by the P2TR decoder). Returns nil
// on invalid input or a non-zero pad.
func btcConvert5to8(data []int) []byte {
	var acc uint32
	var bits int
	out := make([]byte, 0, len(data)*5/8+1)
	for _, value := range data {
		if value < 0 || value>>5 != 0 {
			return nil
		}
		acc = ((acc << 5) | uint32(value)) & 0xffffffff
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte((acc>>uint(bits))&0xff))
		}
	}
	if bits >= 5 {
		return nil
	}
	if (acc<<uint(8-bits))&0xff != 0 {
		return nil
	}
	return out
}

// btcCreateChecksum mirrors the TS createChecksum.
func btcCreateChecksum(hrp string, data5 []int, constant uint32) []int {
	values := append(btcHrpExpand(hrp), data5...)
	mod := btcPolymod(append(values, 0, 0, 0, 0, 0, 0)) ^ constant
	out := make([]int, 6)
	for i := 0; i < 6; i++ {
		out[i] = int((mod >> uint(5*(5-i))) & 31)
	}
	return out
}

// btcEncodeSegwitAddress encodes a SegWit address. witver 0 -> bech32 (P2WPKH);
// witver 1 -> bech32m (P2TR). Returns ("", false) on any invalid input (fail
// closed; never panics). Mirrors the TS encodeSegwitAddress returning null.
func btcEncodeSegwitAddress(hrp string, witver int, program []byte) (string, bool) {
	if witver < 0 || witver > 16 {
		return "", false
	}
	// BIP-141 program length bounds: 2..40 bytes; v0 must be 20 or 32.
	if len(program) < 2 || len(program) > 40 {
		return "", false
	}
	if witver == 0 && len(program) != 20 && len(program) != 32 {
		return "", false
	}

	data5 := btcConvert8to5(program)
	if data5 == nil {
		return "", false
	}
	payload := append([]int{witver}, data5...)
	constant := uint32(btcBech32Const)
	if witver != 0 {
		constant = btcBech32mConst
	}
	checksum := btcCreateChecksum(hrp, payload, constant)
	combined := append(payload, checksum...)

	out := hrp + "1"
	for _, d := range combined {
		if d < 0 || d > 31 {
			return "", false
		}
		out += string(btcCharset[d])
	}
	return out, true
}

// ── Base58Check (Bitcoin alphabet) ──────────────────────────────────────────

const btcBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// btcBase58Encode is plain base58 (big-endian) encode. Mirrors the TS
// base58encode.
func btcBase58Encode(b []byte) string {
	// Count leading zero bytes -> leading '1's.
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}

	// Convert base-256 -> base-58 via repeated division on a digit buffer.
	digits := []int{0}
	for i := zeros; i < len(b); i++ {
		carry := int(b[i])
		for j := 0; j < len(digits); j++ {
			carry += digits[j] << 8
			digits[j] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, carry%58)
			carry /= 58
		}
	}

	out := make([]byte, 0, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out = append(out, btcBase58Alphabet[digits[i]])
	}
	return string(out)
}

// btcBase58CheckEncode encodes version||payload with a sha256d checksum.
// Mirrors the TS base58checkEncode.
func btcBase58CheckEncode(version byte, payload []byte) string {
	data := make([]byte, 0, 1+len(payload))
	data = append(data, version)
	data = append(data, payload...)
	sum := btcSha256d(data)
	full := make([]byte, 0, len(data)+4)
	full = append(full, data...)
	full = append(full, sum[:4]...)
	return btcBase58Encode(full)
}

// btcSha256 / btcSha256d / btcHash160 — hashing helpers. sha256d = double
// SHA-256; hash160 = ripemd160(sha256(x)). Mirror the TS sha256d/hash160.
func btcSha256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func btcSha256d(b []byte) []byte {
	return btcSha256(btcSha256(b))
}
