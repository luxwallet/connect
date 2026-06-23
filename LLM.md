# `@luxwallet/connect`

**Project**: `luxwallet/wallet-connect` — multi-chain wallet connect + Sign-In-With-X.
**Org**: `luxwallet` (the wallet product org; MIT, clean of GPL).
**License**: MIT. **Hard rule: zero GPL deps, ever** — the Uniswap-derived GPL
bones live in `luxfi/exchange` and are eaten away there, never imported here.

## What this is

The one canonical way for any Hanzo/Lux/Zoo/Pars surface to authenticate a
wallet on EVM, Solana, Bitcoin, TON, or XRP. Replaces the EVM-only
`@web3-onboard` path in IAM and becomes the connect layer for the browser
extension (`luxwallet/wallet-connect` → extension) and the native apps
(`luxwallet/unstoppable-wallet-{android,ios}`).

## Decomplected design (Hickey)

- **Values not places**: a login is a `SignedProof` value — `{chain, scheme,
  address, message, signature}` — qualified by the `Chain`/`SignatureScheme`
  unions, not by where it came from.
- **One canonical message**: CAIP-122 (`caip122.ts`). `build ∘ parse` round-trips.
  Every chain signs the *same* human-readable assertion (TON is the exception —
  its `ton_proof` envelope carries the nonce; the verifier handles that).
- **Orthogonal**: connection (browser) and verification (pure crypto) are
  separate. The server only ever needs `verifyProof` — no wallet, no I/O.
- **Fails closed**: unknown scheme / malformed / bad time / bad sig → `{ok:false,
  reason}`. `verifyProof` never throws.
- **DRY across languages**: `go/walletconnect` mirrors `verify.ts` byte-for-byte
  so IAM (casdoor, Go) verifies identically. @noble (not viem) in the verify
  core keeps the crypto portable.

## Layout

```
src/
  types.ts        — Chain, SignatureScheme, Account, LoginChallenge, SignedProof, VerifyResult, WalletConnector
  caip122.ts      — buildSiwxMessage / parseSiwxMessage (pure)
  nonce.ts        — generateNonce / newChallenge
  verify.ts       — verifyProof(proof, expected) dispatcher (pure)
  bytes.ts        — hex/base64/utf8 helpers (cross-runtime)
  evm/verify.ts   — EIP-191 secp256k1 recover  [DONE, tested]
  solana/verify.ts— ed25519 over message       [DONE, tested]
  bitcoin/        — BIP-322                     [TODO]
  ton/            — ton_proof (ed25519)         [TODO]
  xrp/            — signMessage                 [TODO]
  __tests__/      — vitest; verifiers run against generated keypairs
go/walletconnect/ — Go port of verifyProof for IAM  [TODO]
```

## Status (2026-06-22)

- Core + EVM + Solana verifiers: **DONE, 17 tests green** (`pnpm test`).
- Connectors (browser wallet interaction): **TODO** — build on the verifiers.
- Bitcoin (BIP-322) / TON (ton_proof) / XRP verifiers: **TODO** — `verifyProof`
  fails closed (`reason:'unsupported-scheme'`) until each lands.
- Go port for IAM: **TODO**.
- IAM wiring (frontend connectors + `/v1/iam/web3/*` verify against this): **TODO**.

## Consumers (the wallet product line, all under `luxwallet`)

- `luxwallet/wallet-connect` (this) — SDK: web + extension connect/login.
- `luxwallet/unstoppable-wallet-android` — MIT fork of Horizontal Systems (Kotlin). Chains OOTB: BTC, EVM, Solana, TON. **XRP needs a kit.**
- `luxwallet/unstoppable-wallet-ios` — MIT fork (Swift). Same chain coverage.

## Rules for AI assistants

1. **NEVER** add a GPL/AGPL dependency. Connect libs must be MIT/Apache/ISC.
2. **NEVER** put viem/wagmi in the verify core — keep it @noble so the Go port stays 1:1.
3. **ALWAYS** keep `build ∘ parse` round-tripping and `verifyProof` pure + fail-closed.
4. **ALWAYS** add a test (generated keypair → sign → verify true; tamper → false) when adding a verifier.
5. Update THIS file when a chain/connector lands; never spawn parallel `.md`s.
