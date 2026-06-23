/**
 * Solana wallet connector — ed25519 `signMessage` over the CAIP-122 message.
 *
 * Uses the injected provider directly (Phantom `window.solana`, Solflare
 * `window.solflare`) — no adapter library needed; the Wallet Standard surface
 * these expose is a thin `connect()` / `signMessage()` pair. The account
 * address IS the base58 ed25519 public key, which is exactly what
 * {@link verifySolana} needs (it decodes the address as the verifying key).
 *
 * Produced {@link SignedProof}: scheme `ed25519`, base64 signature over the
 * raw UTF-8 message bytes, address = base58 public key.
 */
import bs58 from 'bs58';
import type {
  Account,
  LoginChallenge,
  SignedProof,
  WalletConnector,
  WalletInfo,
} from '../types.js';
import { buildSiwxMessage } from '../caip122.js';
import { utf8ToBytes, bytesToBase64 } from '../bytes.js';

/** Minimal shape of an injected Solana provider (Phantom / Solflare / Backpack). */
interface SolanaProvider {
  isPhantom?: boolean;
  isSolflare?: boolean;
  isBackpack?: boolean;
  publicKey?: { toBytes(): Uint8Array; toString(): string } | null;
  connect(opts?: { onlyIfTrusted?: boolean }): Promise<{ publicKey: { toBytes(): Uint8Array; toString(): string } }>;
  disconnect?(): Promise<void>;
  signMessage(message: Uint8Array, encoding?: 'utf8' | 'hex'): Promise<{ signature: Uint8Array } | Uint8Array>;
}

interface SolanaWindow {
  solana?: SolanaProvider;
  solflare?: SolanaProvider;
  backpack?: SolanaProvider;
}

function getWindow(): SolanaWindow | undefined {
  return typeof window === 'undefined' ? undefined : (window as unknown as SolanaWindow);
}

interface ProviderEntry {
  id: string;
  name: string;
  provider: SolanaProvider;
}

/** Enumerate the injected providers we know how to drive. */
function discover(win: SolanaWindow): ProviderEntry[] {
  const out: ProviderEntry[] = [];
  if (win.solana) {
    out.push({ id: win.solana.isPhantom ? 'phantom' : 'solana', name: win.solana.isPhantom ? 'Phantom' : 'Solana', provider: win.solana });
  }
  if (win.solflare && win.solflare !== win.solana) {
    out.push({ id: 'solflare', name: 'Solflare', provider: win.solflare });
  }
  if (win.backpack && win.backpack !== win.solana) {
    out.push({ id: 'backpack', name: 'Backpack', provider: win.backpack });
  }
  return out;
}

/** Normalize the two shapes signMessage can return into raw signature bytes. */
function extractSignature(res: { signature: Uint8Array } | Uint8Array): Uint8Array {
  if (res instanceof Uint8Array) return res;
  if (res && res.signature instanceof Uint8Array) return res.signature;
  throw new Error('solana: wallet returned an unrecognized signMessage result');
}

export class SolanaConnector implements WalletConnector {
  readonly chain = 'solana' as const;

  #provider: SolanaProvider | null = null;

  async available(): Promise<WalletInfo[]> {
    const win = getWindow();
    if (!win) return [];
    return discover(win).map((e) => ({
      id: e.id,
      name: e.name,
      chain: this.chain,
      installed: true,
    }));
  }

  /** Connect to an injected wallet (Phantom by default) and return the account. */
  async connect(walletId?: string): Promise<Account> {
    const win = getWindow();
    if (!win) throw new Error('solana: no window — connectors are browser-only');

    const entries = discover(win);
    if (entries.length === 0) throw new Error('solana: no injected Solana wallet found');

    const chosen = walletId != null ? entries.find((e) => e.id === walletId) : entries[0];
    if (!chosen) throw new Error(`solana: wallet '${walletId}' not found`);

    const { publicKey } = await chosen.provider.connect();
    const address = bs58.encode(publicKey.toBytes());

    this.#provider = chosen.provider;
    // For Solana the address IS the base58 ed25519 public key — one value.
    return { chain: this.chain, address, publicKey: address, walletId: chosen.id };
  }

  /**
   * Render the CAIP-122 message and have the wallet sign its UTF-8 bytes.
   * Produces an `ed25519` proof whose signature {@link verifySolana} checks
   * against the base58 address (the public key).
   */
  async signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof> {
    if (!this.#provider) throw new Error('solana: not connected — call connect() first');

    const message = buildSiwxMessage({
      challenge,
      address: account.address,
      chain: this.chain,
    });
    const res = await this.#provider.signMessage(utf8ToBytes(message), 'utf8');
    const signature = bytesToBase64(extractSignature(res));

    return {
      chain: this.chain,
      scheme: 'ed25519',
      address: account.address,
      message,
      signature,
    };
  }

  async disconnect(): Promise<void> {
    try {
      await this.#provider?.disconnect?.();
    } finally {
      this.#provider = null;
    }
  }
}
