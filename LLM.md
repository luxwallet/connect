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
  evm/{verify,connect}.ts    — EIP-191 recover [verify] + viem/EIP-6963 [connect]
  solana/{verify,connect}.ts — ed25519 [verify] + injected provider [connect]
  bitcoin/{verify,connect}.ts— legacy+BIP-322 [verify] + sats-connect [connect]
  ton/{verify,connect}.ts    — ton_proof [verify] + @tonconnect/sdk [connect]
  xrp/{verify,connect}.ts    — secp256k1+ed25519 [verify] + @crossmarkio/sdk [connect]
  connectors.ts   — getConnector(chain) factory + allConnectors() barrel
  login.ts        — loginWithWallet({chain, challenge}) — connect→signLogin→SignedProof
  __tests__/      — vitest; verifiers + EVM/Solana connector round-trips (mocked providers)
go/walletconnect/ — Go port of verifyProof for IAM  [DONE, 67 tests]
integrations/iam/ — IAM apply plan + drafts         [planned]
```

## Connectors (browser side) — DONE 2026-06-23

Each `src/<chain>/connect.ts` exports a class implementing `WalletConnector`
(`chain`, `available()`, `connect(walletId?)`, `signLogin(account, challenge)`,
`disconnect()`) producing a `SignedProof` the matching verifier accepts:

- **EVM** — `viem` (MIT). EIP-6963 multi-injection discovery, falls back to
  `window.ethereum`. `personal_sign` → `secp256k1-eip191`.
- **Solana** — injected provider (Phantom/Solflare/Backpack), no lib.
  `signMessage(utf8)` → base64 `ed25519`; address = base58 pubkey.
- **Bitcoin** — `sats-connect` (MIT). Prefers P2WPKH; `signMessage` BIP-322 →
  base64; scheme `bip322` + `extra.addressType` (verifier dispatches by shape).
- **TON** — `@tonconnect/sdk` (Apache-2.0). Lazy-inits the SDK (its ctor touches
  `localStorage`, so `getConnector('ton')` stays pure). `signLogin` re-runs the
  connect handshake with `tonProof: nonce`, builds
  `extra={timestamp,domain,payload,workchain,addressHashHex}`, publicKey hex,
  base64 sig, scheme `ton-proof`. Raw address `<wc>:<hex>` → workchain + hash.
- **XRP** — `@crossmarkio/sdk` (MIT). `signInAndWait(hex(utf8(message)))` →
  `{address, publicKey, signature}`; scheme from the key's family tag
  (`0xED`→`ed25519-xrpl`, else `secp256k1-xrpl`).

**GemWallet NOT wired**: `@gemwallet/api` is a custom dual license (permission
required for public/commercial use), violating the MIT/Apache/ISC-only rule. Its
only non-package path is a hand-rolled `postMessage` protocol (would be slop).
Crossmark covers both XRPL key types, so XRP is complete.

**Architecture rule enforced & verified**: wallet libs are OPTIONAL peer deps
(`peerDependenciesMeta.*.optional`). The `./verify` + `./caip122` entrypoints
import ONLY `@noble/*` + `bs58` — proven three ways (source graph, runtime
require-hook, built `dist/verify.js` graph: 0 wallet-lib leaks). Connectors sit
behind `./connectors`, `./login`, and per-chain `./<chain>/connect` exports.

dual-license note: one transitive dep, `node-forge` (via @crossmarkio/typings),
is `(BSD-3-Clause OR GPL-2.0)` — we elect BSD-3-Clause. No GPL obligation.

## Status (2026-06-22)

- **Verifier core COMPLETE — all 5 chains, both sides. 128 tests green**
  (61 TS via `pnpm test`, 67 Go via `cd go && CGO_ENABLED=0 go test ./...`).
  - TS: EVM (EIP-191), Solana (ed25519), TON (ton_proof), XRP (secp256k1
    sha512half + ed25519, AccountID r-addr), Bitcoin (legacy recoverable ECDSA
    + BIP-322 simple P2WPKH/P2TR). All anchored to KAT vectors where they exist.
  - Go (`go/walletconnect`): same 5, mirrored 1:1, reasons match. EVM via
    `github.com/luxfi/crypto` (no go-ethereum/ava-labs). Bitcoin BIP-340
    implemented inline (dcrd's schnorr is DCRv0, not BIP-340).
- Connectors (browser wallet interaction): **DONE 2026-06-23** — see the
  "Connectors" section below. viem / sats-connect / @tonconnect/sdk /
  @crossmarkio/sdk (all MIT/Apache). EVM + Solana have mocked-provider
  round-trip tests through verifyProof; BTC/TON/XRP need a real wallet to
  exercise end-to-end (their crypto is covered by the verifier round-trips).
- IAM apply: **planned** in `integrations/iam/` (PLAN.md + drafts). Needs the Go
  module published + `replace` dropped, then `/v1/iam/web3/{nonce,verify}` +
  nonce store + WalletLink table wired, `@web3-onboard` + dead idp removed.
  NB: current IAM web3 login verifies NO signature (security hole this closes).
- Mobile (`luxwallet/unstoppable-wallet-{android,ios}`): forked + rebranded to
  "Lux Wallet"/`network.lux.wallet` on `lux-rebrand` branches. XRP needs a
  MarketKit fork + new `ripple-kit` libs (no upstream HS kit).

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
