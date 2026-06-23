# @luxwallet/connect

Multi-chain wallet connect + **Sign-In-With-X** for **EVM, Solana, Bitcoin, TON, XRP**.

One vocabulary, one canonical login message ([CAIP-122](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md)),
one verifier. **MIT licensed — zero GPL.** This is the clean wallet stack; the
Uniswap-derived GPL bones stay quarantined in `luxfi/exchange`.

## Why

`@luxfi/wallet` (Uniswap "Universe" fork) is GPL-3.0 and EVM-only. This package
is a from-scratch, permissively-licensed connector that any Hanzo/Lux/Zoo/Pars
surface — `hanzo.id` login, the browser extension, web and mobile apps — can use
to authenticate a wallet on **any** supported chain.

## Architecture

```
connect(chain) ─► Account ─► signLogin(challenge) ─► SignedProof ─► verifyProof()
                  (browser, per-chain connector)      (server, one pure fn)
```

- **`caip122.ts`** — render/parse the canonical login message. `build ∘ parse` round-trips.
- **`verify.ts`** — `verifyProof(proof, expected)`: parse → enforce domain/nonce/time → dispatch to the per-chain crypto verifier. Pure, fails closed, never throws.
- **`<chain>/`** — per-chain connector (browser) + verifier (pure crypto).
- **`go/walletconnect`** — Go port of `verifyProof`, imported by Hanzo IAM so the server verifies identically.

## Chain support

| Chain | Connect lib | Login proof | Verifier |
|-------|-------------|-------------|----------|
| EVM | viem/wagmi + WalletConnect | EIP-191 `personal_sign` | ✅ secp256k1 recover |
| Solana | `@solana/wallet-adapter` | ed25519 `signMessage` | ✅ ed25519 |
| Bitcoin | `sats-connect` (Xverse/Leather/Unisat) | BIP-322 | ⏳ in progress |
| TON | `@tonconnect/ui` | `ton_proof` | ⏳ in progress |
| XRP | GemWallet / Crossmark / Xaman | `signMessage` | ⏳ in progress |

All connect libs are MIT/Apache — no GPL anywhere in the dependency tree.

## Use

```ts
// Server: mint a challenge
import { newChallenge, verifyProof } from '@luxwallet/connect';
const challenge = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id/login' });
// → store challenge.nonce, send challenge to the client

// Server: verify what comes back
const res = verifyProof(proof, { domain: 'hanzo.id', nonce: challenge.nonce });
if (res.ok) { /* res.address is authenticated on res.chain */ }
```

## Develop

```bash
pnpm install
pnpm test        # vitest — crypto verifiers run against generated keypairs
pnpm typecheck
pnpm build
```

## License

MIT © Lux Industries Inc.
