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

| Chain | Connect lib (license) | Login proof | Connector | Verifier |
|-------|-----------------------|-------------|-----------|----------|
| EVM | `viem` (MIT) — EIP-6963 / `window.ethereum` | EIP-191 `personal_sign` | ✅ `evm/connect.ts` | ✅ secp256k1 recover |
| Solana | injected provider (Phantom/Solflare/Backpack) | ed25519 `signMessage` | ✅ `solana/connect.ts` | ✅ ed25519 |
| Bitcoin | `sats-connect` (MIT) — Xverse/Leather/Unisat | BIP-322 | ✅ `bitcoin/connect.ts` | ✅ legacy + BIP-322 |
| TON | `@tonconnect/sdk` (Apache-2.0) | `ton_proof` | ✅ `ton/connect.ts` | ✅ ed25519 envelope |
| XRP | `@crossmarkio/sdk` (MIT) — Crossmark | `signInAndWait` | ✅ `xrp/connect.ts` | ✅ secp256k1 + ed25519 |

All connect libs are MIT/Apache/ISC — **no GPL anywhere** in the dependency tree.
GemWallet is intentionally not wired: its only client, `@gemwallet/api`, ships
under a custom dual license requiring GemWallet's permission for public/commercial
use — incompatible with the MIT/Apache/ISC-only rule. Crossmark covers both XRPL
key types, so the XRP path is complete without it.

### Architecture: server verify never pulls a wallet lib

The wallet libraries are **optional peer dependencies**. The server-side
`verifyProof` path imports only `@noble/*` + `bs58`:

```ts
import { verifyProof } from '@luxwallet/connect/verify';     // zero wallet libs
import { buildSiwxMessage } from '@luxwallet/connect/caip122'; // zero deps
```

Connectors live behind separate entrypoints, so a server bundle stays clean:

```ts
import { loginWithWallet, getConnector } from '@luxwallet/connect/connectors';
import { EvmConnector } from '@luxwallet/connect/evm/connect';
```

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

```ts
// Client (browser): connect a wallet and sign the challenge in one call.
import { loginWithWallet } from '@luxwallet/connect/connectors';

const { account, proof } = await loginWithWallet({ chain: 'evm', challenge });
// → POST `proof` to the server, which calls verifyProof(proof, { domain, nonce }).

// Or drive a connector directly:
import { getConnector } from '@luxwallet/connect/connectors';
const c = getConnector('solana');
const acct = await c.connect();             // provider.connect()
const p = await c.signLogin(acct, challenge); // ed25519 signMessage → SignedProof
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
