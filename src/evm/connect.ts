/**
 * EVM wallet connector — EIP-191 `personal_sign` over the CAIP-122 message.
 *
 * Discovery: EIP-6963 multi-injection (`window.dispatchEvent` /
 * `eip6963:requestProvider`) when wallets announce themselves, with a fallback
 * to the legacy single `window.ethereum`. Connection uses viem's `custom`
 * transport over the chosen EIP-1193 provider; signing uses `personal_sign`.
 *
 * The produced {@link SignedProof} is exactly what {@link verifyEvm} accepts:
 * a 65-byte hex signature, address recoverable from it, scheme
 * `secp256k1-eip191`. viem stays out of the verify core (see ../verify.ts) —
 * it lives here, on the browser side only.
 */
import {
  createWalletClient,
  custom,
  getAddress as toChecksum,
  type WalletClient,
  type EIP1193Provider,
} from 'viem';
import type {
  Account,
  LoginChallenge,
  SignedProof,
  WalletConnector,
  WalletInfo,
} from '../types.js';
import { buildSiwxMessage } from '../caip122.js';

/** EIP-6963 provider announcement detail. */
interface Eip6963ProviderInfo {
  uuid: string;
  name: string;
  icon: string;
  rdns: string;
}
interface Eip6963ProviderDetail {
  info: Eip6963ProviderInfo;
  provider: EIP1193Provider;
}

interface Eip6963AnnounceEvent extends Event {
  detail: Eip6963ProviderDetail;
}

/** A discovered injected provider, keyed by a stable id. */
interface DiscoveredProvider {
  id: string;
  name: string;
  icon?: string;
  provider: EIP1193Provider;
}

/** window shape we touch — kept local so the browser libs stay optional. */
interface EvmWindow {
  ethereum?: EIP1193Provider & { providers?: EIP1193Provider[] };
  addEventListener?: typeof addEventListener;
  removeEventListener?: typeof removeEventListener;
  dispatchEvent?: typeof dispatchEvent;
}

function getWindow(): EvmWindow | undefined {
  return typeof window === 'undefined' ? undefined : (window as unknown as EvmWindow);
}

/**
 * Collect EIP-6963 providers. Wallets respond to `eip6963:requestProvider`
 * synchronously by dispatching `eip6963:announceProvider`; we listen for a
 * short window and dedupe by rdns.
 */
function discoverEip6963(win: EvmWindow, waitMs = 300): Promise<DiscoveredProvider[]> {
  if (typeof win.addEventListener !== 'function' || typeof win.dispatchEvent !== 'function') {
    return Promise.resolve([]);
  }
  return new Promise((resolve) => {
    const byRdns = new Map<string, DiscoveredProvider>();
    const onAnnounce = (ev: Event): void => {
      const e = ev as Eip6963AnnounceEvent;
      const d = e.detail;
      if (d?.info?.rdns && d.provider && !byRdns.has(d.info.rdns)) {
        byRdns.set(d.info.rdns, {
          id: d.info.rdns,
          name: d.info.name,
          icon: d.info.icon,
          provider: d.provider,
        });
      }
    };
    win.addEventListener!('eip6963:announceProvider', onAnnounce as EventListener);
    win.dispatchEvent!(new Event('eip6963:requestProvider'));
    setTimeout(() => {
      win.removeEventListener?.('eip6963:announceProvider', onAnnounce as EventListener);
      resolve([...byRdns.values()]);
    }, waitMs);
  });
}

/** Legacy fallback: window.ethereum (and any window.ethereum.providers fan-out). */
function discoverLegacy(win: EvmWindow): DiscoveredProvider[] {
  const eth = win.ethereum;
  if (!eth) return [];
  const list = Array.isArray(eth.providers) && eth.providers.length > 0 ? eth.providers : [eth];
  return list.map((provider, i) => ({
    id: i === 0 ? 'injected' : `injected-${i}`,
    name: 'Injected Wallet',
    provider,
  }));
}

export class EvmConnector implements WalletConnector {
  readonly chain = 'evm' as const;

  #provider: EIP1193Provider | null = null;
  #client: WalletClient | null = null;

  /** Discover injected EVM wallets via EIP-6963, falling back to window.ethereum. */
  async available(): Promise<WalletInfo[]> {
    const win = getWindow();
    if (!win) return [];
    const discovered = await this.#discover(win);
    return discovered.map((d) => ({
      id: d.id,
      name: d.name,
      chain: this.chain,
      icon: d.icon,
      installed: true,
    }));
  }

  async #discover(win: EvmWindow): Promise<DiscoveredProvider[]> {
    const announced = await discoverEip6963(win);
    if (announced.length > 0) return announced;
    return discoverLegacy(win);
  }

  /**
   * Connect to an injected wallet. `walletId` selects an EIP-6963 provider by
   * its rdns (or the legacy `injected[-n]` id); omit it to use the first.
   */
  async connect(walletId?: string): Promise<Account> {
    const win = getWindow();
    if (!win) throw new Error('evm: no window — connectors are browser-only');

    const discovered = await this.#discover(win);
    if (discovered.length === 0) {
      throw new Error('evm: no injected EVM wallet found');
    }
    const chosen = walletId != null ? discovered.find((d) => d.id === walletId) : discovered[0];
    if (!chosen) {
      throw new Error(`evm: wallet '${walletId}' not found`);
    }

    const provider = chosen.provider;
    const accounts = (await provider.request({ method: 'eth_requestAccounts' })) as string[];
    if (!Array.isArray(accounts) || accounts.length === 0) {
      throw new Error('evm: wallet returned no accounts');
    }
    const address = toChecksum(accounts[0]!);

    let caip2: string | undefined;
    try {
      const chainIdHex = (await provider.request({ method: 'eth_chainId' })) as string;
      const chainId = Number.parseInt(chainIdHex, 16);
      if (Number.isFinite(chainId)) caip2 = `eip155:${chainId}`;
    } catch {
      // chainId is best-effort; signing does not require it.
    }

    this.#provider = provider;
    this.#client = createWalletClient({ account: address, transport: custom(provider) });

    return { chain: this.chain, address, walletId: chosen.id, caip2 };
  }

  /**
   * Render the CAIP-122 message and have the wallet `personal_sign` it.
   * Produces a `secp256k1-eip191` proof: 65-byte hex signature over the EIP-191
   * digest, with the signer recoverable from the signature.
   */
  async signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof> {
    if (!this.#client || !this.#provider) {
      throw new Error('evm: not connected — call connect() first');
    }
    const chainId = account.caip2 ?? undefined;
    const message = buildSiwxMessage({
      challenge,
      address: account.address,
      chain: this.chain,
      chainId,
    });

    // personal_sign returns a 0x-prefixed 65-byte signature (r‖s‖v).
    const signature = await this.#client.signMessage({
      account: account.address as `0x${string}`,
      message,
    });

    return {
      chain: this.chain,
      scheme: 'secp256k1-eip191',
      address: account.address,
      message,
      signature,
    };
  }

  async disconnect(): Promise<void> {
    this.#provider = null;
    this.#client = null;
  }
}
