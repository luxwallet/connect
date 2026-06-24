/**
 * Polkadot (Substrate) wallet connector — `signRaw({ type: 'bytes' })` over the
 * CAIP-122 message via the injected extension API (`window.injectedWeb3`:
 * polkadot.js / Talisman / SubWallet / Nova, …).
 *
 * Handshake (the Substrate "dapp" protocol, no SDK needed — the injected
 * surface is a thin `enable()` → `{ accounts, signer }` pair):
 *   1. `enable(originName)` the extension.
 *   2. `accounts.get()` → pick the first account (its SS58 `address`, the raw
 *      `genesisHash`-agnostic public key, and key `type`: sr25519/ed25519/ecdsa).
 *   3. `signer.signRaw({ address, data: hex(message), type: 'bytes' })` — the
 *      extension WRAPS the message as `<Bytes>…</Bytes>` and signs the wrap;
 *      {@link verifyPolkadot} reconstructs that wrap to verify.
 *
 * The produced {@link SignedProof} carries scheme `sr25519` (default) /
 * `ed25519-substrate` / `ecdsa-substrate`, the SS58 `address`, the hex
 * `publicKey`, and the hex `signature` — exactly what the verifier needs.
 *
 * No hard dependency: this drives the raw injected API. `@polkadot/extension-dapp`
 * is an OPTIONAL convenience the host app may use to obtain the same surface;
 * the verify core pulls neither.
 */
import type {
  Account,
  LoginChallenge,
  SignatureScheme,
  SignedProof,
  WalletConnector,
  WalletInfo,
} from '../types.js';
import { buildSiwxMessage } from '../caip122.js';
import { utf8ToBytes, bytesToHex } from '../bytes.js';

/** Substrate key types the extension reports → our scheme tags. */
function schemeFor(keyType: string | undefined): SignatureScheme {
  switch (keyType) {
    case 'ed25519':
      return 'ed25519-substrate';
    case 'ecdsa':
    case 'ethereum':
      return 'ecdsa-substrate';
    case 'sr25519':
    default:
      return 'sr25519'; // Substrate default.
  }
}

/** A single account as exposed by the injected extension's accounts API. */
interface InjectedAccount {
  address: string;
  /** Optional human name. */
  name?: string;
  /** Key type: 'sr25519' | 'ed25519' | 'ecdsa' | 'ethereum'. */
  type?: string;
}

interface InjectedAccounts {
  get(anyType?: boolean): Promise<InjectedAccount[]>;
}

interface SignRawPayload {
  address: string;
  /** Hex (0x-prefixed) of the bytes to sign. */
  data: string;
  type: 'bytes' | 'payload';
}

interface InjectedSigner {
  signRaw?(payload: SignRawPayload): Promise<{ id: number; signature: string }>;
}

interface InjectedExtension {
  accounts: InjectedAccounts;
  signer: InjectedSigner;
}

/** What an entry in `window.injectedWeb3[id]` looks like before `enable()`. */
interface InjectedWindowProvider {
  enable(originName: string): Promise<InjectedExtension>;
  version?: string;
}

interface PolkadotWindow {
  injectedWeb3?: Record<string, InjectedWindowProvider>;
}

function getWindow(): PolkadotWindow | undefined {
  return typeof window === 'undefined' ? undefined : (window as unknown as PolkadotWindow);
}

const ORIGIN = 'hanzo.id';

/** Friendly names for the wallets we commonly see. */
const WALLET_NAMES: Record<string, string> = {
  'polkadot-js': 'Polkadot.js',
  talisman: 'Talisman',
  'subwallet-js': 'SubWallet',
  'nova-wallet': 'Nova Wallet',
  enkrypt: 'Enkrypt',
};

/** Decode the extension's signature (hex 0x…) to a hex string without 0x. */
function normalizeSig(sig: string): string {
  const s = sig.trim();
  return s.startsWith('0x') || s.startsWith('0X') ? s : `0x${s}`;
}

export class PolkadotConnector implements WalletConnector {
  readonly chain = 'polkadot' as const;

  #extension: InjectedExtension | null = null;
  #scheme: SignatureScheme = 'sr25519';

  async available(): Promise<WalletInfo[]> {
    const win = getWindow();
    if (!win?.injectedWeb3) return [];
    return Object.keys(win.injectedWeb3).map((id) => ({
      id,
      name: WALLET_NAMES[id] ?? id,
      chain: this.chain,
      installed: true,
    }));
  }

  /** Enable the chosen extension and return its first account. */
  async connect(walletId?: string): Promise<Account> {
    const win = getWindow();
    if (!win) throw new Error('polkadot: no window — connectors are browser-only');
    const injected = win.injectedWeb3;
    if (!injected || Object.keys(injected).length === 0) {
      throw new Error('polkadot: no injected Substrate wallet found');
    }

    const id = walletId ?? Object.keys(injected)[0]!;
    const provider = injected[id];
    if (!provider) throw new Error(`polkadot: wallet '${id}' not found`);

    const ext = await provider.enable(ORIGIN);
    const accounts = await ext.accounts.get(true);
    if (accounts.length === 0) {
      throw new Error('polkadot: extension returned no accounts (none authorized?)');
    }
    const first = accounts[0]!;

    this.#extension = ext;
    this.#scheme = schemeFor(first.type);

    // The connector cannot recover the raw public key from the SS58 address
    // without @polkadot/util-crypto (kept out of the connector's hard deps), so
    // it asks the verifier-side to bind via SS58 decode. We still surface the
    // public key when the extension provides it directly; otherwise the SS58
    // address carries it (the verifier decodes it). Most extensions expose only
    // the address, so we leave publicKey to be filled by the verifier's decode.
    return {
      chain: this.chain,
      address: first.address,
      walletId: id,
    };
  }

  /**
   * Render the CAIP-122 message and have the extension sign its bytes via
   * `signRaw({ type: 'bytes' })`. The extension wraps the message as
   * `<Bytes>…</Bytes>` before signing; {@link verifyPolkadot} reconstructs that.
   *
   * `publicKey` is required by the verifier. When the extension did not expose
   * it at connect time we derive it from the SS58 address using the OPTIONAL
   * `@polkadot/util-crypto` (loaded lazily here, on the browser side only —
   * never by the verify core).
   */
  async signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof> {
    if (!this.#extension?.signer.signRaw) {
      throw new Error('polkadot: not connected or extension cannot signRaw — call connect() first');
    }

    const message = buildSiwxMessage({
      challenge,
      address: account.address,
      chain: this.chain,
    });

    const dataHex = `0x${bytesToHex(utf8ToBytes(message))}`;
    const { signature } = await this.#extension.signer.signRaw({
      address: account.address,
      data: dataHex,
      type: 'bytes',
    });

    const publicKey = account.publicKey ?? (await this.#publicKeyFromAddress(account.address));

    return {
      chain: this.chain,
      scheme: this.#scheme,
      address: account.address,
      publicKey,
      message,
      signature: normalizeSig(signature),
    };
  }

  async disconnect(): Promise<void> {
    this.#extension = null;
  }

  /** Recover the hex public key from an SS58 address (optional dep, browser-side). */
  async #publicKeyFromAddress(address: string): Promise<string> {
    const { decodeAddress } = await import('@polkadot/util-crypto');
    return bytesToHex(decodeAddress(address));
  }
}
