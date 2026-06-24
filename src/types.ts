/**
 * @luxwallet/connect — core types.
 *
 * One vocabulary across every chain. A wallet on any chain produces a
 * {@link SignedProof}; the server verifies it with one {@link verifyProof}
 * call. The login message itself is chain-agnostic (CAIP-122 "Sign-In-With-X").
 */

/** Supported chain families. Values, not places — namespaced by this union. */
export type Chain = 'evm' | 'solana' | 'bitcoin' | 'ton' | 'xrp' | 'polkadot';

export const CHAINS: readonly Chain[] = ['evm', 'solana', 'bitcoin', 'ton', 'xrp', 'polkadot'];

/**
 * Signature scheme used to produce a proof. The verifier dispatches on this,
 * not on {@link Chain}, so a chain could in principle offer more than one.
 */
export type SignatureScheme =
  | 'secp256k1-eip191' // EVM personal_sign (EIP-191)
  | 'ed25519' // Solana, TON
  | 'bip322' // Bitcoin message signing (BIP-322)
  | 'ton-proof' // TON Connect ton_proof envelope (ed25519 inside)
  | 'secp256k1-xrpl' // XRPL signMessage
  | 'ed25519-xrpl' // XRPL ed25519 keypair
  | 'sr25519' // Polkadot/Substrate default (Schnorrkel over Ristretto255)
  | 'ed25519-substrate' // Polkadot/Substrate ed25519 accounts
  | 'ecdsa-substrate'; // Polkadot/Substrate ecdsa (secp256k1) accounts

/** A connected wallet account. `publicKey` is required where the address is not recoverable from the signature (Solana, TON, XRP). */
export interface Account {
  chain: Chain;
  /** Canonical address string for the chain (checksum EVM, base58 Solana, etc.). */
  address: string;
  /** Raw public key, hex (no 0x) or base64 — needed by ed25519/XRPL verifiers. */
  publicKey?: string;
  /** Identifier of the wallet that produced it (e.g. 'metamask', 'phantom'). */
  walletId: string;
  /** CAIP-2 chain id of the specific network, when known (e.g. 'eip155:1'). */
  caip2?: string;
}

/**
 * The login challenge a server asks a wallet to sign. Mirrors EIP-4361 /
 * CAIP-122 fields. The server mints `nonce` and stores it until verification.
 */
export interface LoginChallenge {
  /** RFC 4501 dnsauthority that is requesting the signing (e.g. 'hanzo.id'). */
  domain: string;
  /** RFC 3986 URI referring to the resource that is the subject of the signing. */
  uri: string;
  /** Human-readable assertion the user signs (one line, no newlines). */
  statement?: string;
  /** Server-minted single-use nonce (>= 8 alphanumerics). */
  nonce: string;
  /** ISO-8601 issuance time. */
  issuedAt: string;
  /** ISO-8601 expiry; after this the proof is rejected. */
  expirationTime?: string;
  /** ISO-8601 not-before; before this the proof is rejected. */
  notBefore?: string;
  /** Opaque request correlation id. */
  requestId?: string;
  /** Version of the message spec; '1' for CAIP-122/EIP-4361. */
  version?: string;
  /** Resource URIs the sign-in grants access to. */
  resources?: string[];
}

/** What a wallet hands back after signing — everything a server needs to verify. */
export interface SignedProof {
  chain: Chain;
  scheme: SignatureScheme;
  /** Address that signed (must match the address embedded in `message`). */
  address: string;
  /** Public key (hex/base64) when required by the scheme. */
  publicKey?: string;
  /** The exact UTF-8 string that was signed (the rendered CAIP-122 message). */
  message: string;
  /** Signature bytes, hex (0x-prefixed allowed) or base64 per scheme. */
  signature: string;
  /** Scheme-specific extra fields (e.g. TON proof envelope, BTC address type). */
  extra?: Record<string, unknown>;
}

/** Server-side expectations checked against the parsed message during verify. */
export interface VerifyExpectation {
  /** Must equal the message `domain`. */
  domain: string;
  /** Must equal the message `nonce` (single-use; server also burns it). */
  nonce: string;
  /** Optional: require an exact address (case-insensitive for EVM). */
  address?: string;
  /** Override "now" for deterministic tests (epoch ms). */
  now?: number;
  /** Max clock skew tolerated on issuedAt/notBefore, ms. Default 5 min. */
  clockSkewMs?: number;
}

export interface VerifyResult {
  ok: boolean;
  /** Present when ok=false: machine-readable reason. */
  reason?:
    | 'bad-signature'
    | 'address-mismatch'
    | 'domain-mismatch'
    | 'nonce-mismatch'
    | 'expired'
    | 'not-yet-valid'
    | 'malformed-message'
    | 'unsupported-scheme'
    | 'missing-public-key';
  /** The verified address (canonicalized) when ok=true. */
  address?: string;
  chain?: Chain;
}

/**
 * A per-chain connector. Browser/runtime side only — the verifier never needs
 * it. Implementations live under src/<chain>/.
 */
export interface WalletConnector {
  readonly chain: Chain;
  /** Wallets this connector can discover/offer in the current runtime. */
  available(): Promise<WalletInfo[]>;
  /** Connect (optionally to a specific wallet) and return the active account. */
  connect(walletId?: string): Promise<Account>;
  /** Render the challenge to the canonical message and have the wallet sign it. */
  signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof>;
  /** Disconnect / forget the session. */
  disconnect(): Promise<void>;
}

export interface WalletInfo {
  id: string;
  name: string;
  chain: Chain;
  /** Data URI or URL to the wallet icon. */
  icon?: string;
  /** True if detected/installed in the current runtime. */
  installed: boolean;
  /** Where to get it if not installed. */
  downloadUrl?: string;
}
