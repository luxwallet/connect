/**
 * TON wallet connector — TON Connect `ton_proof` (ed25519).
 *
 * TON differs from text-signing chains: the wallet does not sign the CAIP-122
 * string. It signs a structured `ton_proof` envelope whose `payload` we pin to
 * the server nonce, and returns the ed25519 signature plus the domain /
 * timestamp it bound in. {@link verifyTon} reconstructs that envelope and
 * checks the signature, then binds it back to the CAIP-122 message
 * (nonce === payload, address === signer).
 *
 * Because TON Connect binds the proof payload at connect time, `signLogin`
 * re-runs the connect handshake with `tonProof: challenge.nonce` and waits for
 * the wallet's `ton_proof` reply. The produced {@link SignedProof} carries:
 *   - scheme `ton-proof`
 *   - publicKey: ed25519 key, hex
 *   - signature: base64
 *   - extra: { timestamp, domain, payload, workchain, addressHashHex }
 */
import TonConnect, {
  isWalletInfoCurrentlyInjected,
  type Wallet,
  type WalletInfo as TonWalletInfo,
  type TonProofItemReply,
} from '@tonconnect/sdk';
import type {
  Account,
  LoginChallenge,
  SignedProof,
  WalletConnector,
  WalletInfo,
} from '../types.js';
import { buildSiwxMessage } from '../caip122.js';

/** Default manifest URL used when the host page does not supply one. */
const DEFAULT_MANIFEST = 'https://hanzo.id/tonconnect-manifest.json';

export interface TonConnectorOptions {
  /** TON Connect dApp manifest URL (defaults to hanzo.id's). */
  manifestUrl?: string;
}

/** A successful ton_proof reply (the only variant we accept). */
function readProof(reply: TonProofItemReply | undefined): {
  timestamp: number;
  domain: string;
  payload: string;
  signature: string;
} | null {
  if (!reply || reply.name !== 'ton_proof' || !('proof' in reply)) return null;
  const p = reply.proof;
  return { timestamp: p.timestamp, domain: p.domain.value, payload: p.payload, signature: p.signature };
}

/** Split a raw TON address `"<workchain>:<hex>"` into its parts. */
function parseRawAddress(address: string): { workchain: number; addressHashHex: string } | null {
  const i = address.indexOf(':');
  if (i < 0) return null;
  const workchain = Number.parseInt(address.slice(0, i), 10);
  const addressHashHex = address.slice(i + 1);
  if (!Number.isInteger(workchain)) return null;
  if (!/^[0-9a-fA-F]{64}$/.test(addressHashHex)) return null;
  return { workchain, addressHashHex };
}

export class TonConnector implements WalletConnector {
  readonly chain = 'ton' as const;

  readonly #manifestUrl: string;
  #connector: TonConnect | null = null;

  constructor(options: TonConnectorOptions = {}) {
    // Pure construction: TonConnect's constructor touches localStorage, so it is
    // created lazily on first use (in a browser) rather than here.
    this.#manifestUrl = options.manifestUrl ?? DEFAULT_MANIFEST;
  }

  /** Lazily build the underlying TonConnect (requires a browser w/ localStorage). */
  #sdk(): TonConnect {
    if (typeof window === 'undefined') {
      throw new Error('ton: no window — connectors are browser-only');
    }
    if (!this.#connector) {
      this.#connector = new TonConnect({ manifestUrl: this.#manifestUrl });
    }
    return this.#connector;
  }

  /** List injected TON wallets (Tonkeeper, MyTonWallet, …) detected on the page. */
  async available(): Promise<WalletInfo[]> {
    if (typeof window === 'undefined') return [];
    const wallets = await this.#sdk().getWallets();
    return wallets.filter(isWalletInfoCurrentlyInjected).map((w: TonWalletInfo) => ({
      id: (w as { jsBridgeKey: string }).jsBridgeKey,
      name: w.name,
      chain: this.chain,
      icon: w.imageUrl,
      installed: true,
    }));
  }

  /**
   * Establish a session (no proof yet) and return the account. `walletId` is the
   * wallet's `jsBridgeKey`; omit it to use the first injected wallet.
   */
  async connect(walletId?: string): Promise<Account> {
    const wallet = await this.#handshake(walletId);
    return this.#toAccount(wallet, walletId);
  }

  /**
   * Re-run the handshake with `tonProof: nonce`, wait for the wallet's signed
   * envelope, and assemble the {@link SignedProof} {@link verifyTon} accepts.
   */
  async signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof> {
    const parsed = parseRawAddress(account.address);
    if (!parsed) throw new Error(`ton: address '${account.address}' is not raw '<wc>:<hex>' form`);

    // Bind the ton_proof payload to the server nonce.
    const wallet = await this.#handshake(account.walletId, challenge.nonce);

    const publicKey = wallet.account.publicKey;
    if (!publicKey) throw new Error('ton: wallet did not return a public key');

    const proof = readProof(wallet.connectItems?.tonProof);
    if (!proof) throw new Error('ton: wallet did not return a ton_proof');
    if (proof.payload !== challenge.nonce) {
      throw new Error('ton: wallet signed a different payload than the requested nonce');
    }

    // CAIP-122 message: address line is the raw TON address; its Nonce equals
    // the ton_proof payload (the verifier enforces both bindings).
    const message = buildSiwxMessage({
      challenge,
      address: account.address,
      chain: this.chain,
    });

    return {
      chain: this.chain,
      scheme: 'ton-proof',
      address: account.address,
      publicKey,
      message,
      signature: proof.signature,
      extra: {
        timestamp: proof.timestamp,
        domain: proof.domain,
        payload: proof.payload,
        workchain: parsed.workchain,
        addressHashHex: parsed.addressHashHex,
      },
    };
  }

  async disconnect(): Promise<void> {
    // Only act if the SDK was ever created (avoids touching localStorage in SSR).
    if (this.#connector?.connected) await this.#connector.disconnect();
  }

  /** Resolve the chosen injected wallet's jsBridgeKey. */
  async #resolveBridgeKey(walletId?: string): Promise<string> {
    if (walletId != null) return walletId;
    const wallets = (await this.#sdk().getWallets()).filter(isWalletInfoCurrentlyInjected);
    const first = wallets[0] as { jsBridgeKey?: string } | undefined;
    if (!first?.jsBridgeKey) throw new Error('ton: no injected TON wallet found');
    return first.jsBridgeKey;
  }

  /**
   * Drive one connect handshake and resolve with the resulting Wallet. When
   * `proofPayload` is given, the wallet returns a ton_proof bound to it.
   */
  async #handshake(walletId?: string, proofPayload?: string): Promise<Wallet> {
    const sdk = this.#sdk(); // throws outside a browser
    const jsBridgeKey = await this.#resolveBridgeKey(walletId);

    return new Promise<Wallet>((resolve, reject) => {
      let unsubscribe: (() => void) | undefined;
      const done = (fn: () => void): void => {
        unsubscribe?.();
        fn();
      };
      unsubscribe = sdk.onStatusChange(
        (wallet) => {
          if (wallet) done(() => resolve(wallet));
        },
        (err) => done(() => reject(err)),
      );
      try {
        // Injected connect returns void; the reply arrives via onStatusChange.
        sdk.connect(
          { jsBridgeKey },
          proofPayload != null ? { tonProof: proofPayload } : undefined,
        );
      } catch (err) {
        done(() => reject(err instanceof Error ? err : new Error(String(err))));
      }
    });
  }

  #toAccount(wallet: Wallet, walletId?: string): Account {
    return {
      chain: this.chain,
      address: wallet.account.address,
      publicKey: wallet.account.publicKey,
      walletId: walletId ?? wallet.device.appName,
      caip2: `ton:${wallet.account.chain}`,
    };
  }
}
