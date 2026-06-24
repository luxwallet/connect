package walletconnect

import (
	"encoding/hex"
	"strconv"
	"strings"

	luxcrypto "github.com/luxfi/crypto"
)

// EVM verifier — EIP-191 personal_sign over the CAIP-122 message.
//
// Recovers the secp256k1 public key from the signature, derives the Ethereum
// address (keccak256 of the uncompressed pubkey body, last 20 bytes), and
// compares it case-insensitively to the claimed address. Crypto comes from
// github.com/luxfi/crypto (NOT go-ethereum, NOT ava-labs) so this mirrors the
// TS @noble implementation 1:1.

// EIP191Digest computes keccak256("\x19Ethereum Signed Message:\n"+len+msg).
// Mirrors the TS eip191Digest.
func EIP191Digest(message string) []byte {
	msg := []byte(message)
	prefix := []byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(msg)))
	return luxcrypto.Keccak256(prefix, msg)
}

// AddressFromPublicKey returns the lowercase 0x-address derived from an
// uncompressed (65-byte) secp256k1 public key. Mirrors the TS
// addressFromPublicKey: drop the 0x04 prefix, keccak256 the 64-byte body, take
// the last 20 bytes. No EIP-55 checksum (lowercase hex), matching the TS.
func AddressFromPublicKey(pubUncompressed []byte) string {
	body := pubUncompressed
	if len(pubUncompressed) == 65 {
		body = pubUncompressed[1:]
	}
	hash := luxcrypto.Keccak256(body)
	return "0x" + hex.EncodeToString(hash[len(hash)-20:])
}

// RecoverEvmAddress verifies an EIP-191 signature and returns the recovered
// lowercase address, or ("", false) if the signature is malformed or
// unrecoverable. Mirrors the TS recoverEvmAddress, including the 65-byte length
// check and the 27/28-or-0/1 recovery-id normalisation.
func RecoverEvmAddress(message, signature string) (string, bool) {
	// Bound inputs before hashing the message / decoding the sig (DoS guard;
	// also makes this exported helper safe when called outside the dispatcher).
	if len(message) > maxMessageLen || len(signature) > maxSignatureLen {
		return "", false
	}
	sig, err := hexToBytes(signature)
	if err != nil {
		return "", false
	}
	if len(sig) != 65 {
		return "", false
	}
	v := sig[64]
	// Accept 27/28 (Ethereum) and raw 0/1 recovery ids.
	if v >= 27 {
		v -= 27
	}
	if v != 0 && v != 1 {
		return "", false
	}
	// luxfi/crypto.SigToPub expects [R || S || V] with V as 0/1.
	rsv := make([]byte, 65)
	copy(rsv, sig[:64])
	rsv[64] = v

	digest := EIP191Digest(message)
	pub, err := luxcrypto.SigToPub(digest, rsv)
	if err != nil {
		return "", false
	}
	return AddressFromPublicKey(luxcrypto.FromECDSAPub(pub)), true
}

// VerifyEVM reports whether signature over message was produced by address.
// Mirrors the TS verifyEvm (case-insensitive address comparison).
func VerifyEVM(message, signature, address string) bool {
	if len(address) == 0 || len(address) > maxAddressLen {
		return false
	}
	recovered, ok := RecoverEvmAddress(message, signature)
	if !ok {
		return false
	}
	return strings.EqualFold(recovered, strings.TrimSpace(address))
}
