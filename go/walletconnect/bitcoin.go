package walletconnect

// VerifyBitcoin verifies a Bitcoin login-message signature: legacy "Bitcoin
// Signed Message" (recoverable ECDSA) plus BIP-322 simple (P2WPKH/P2TR), with
// P2PKH/P2WPKH/P2TR address binding. Port of src/bitcoin/verify.ts.
// Stub: fails closed until implemented.
func VerifyBitcoin(_ Proof) bool { return false }
