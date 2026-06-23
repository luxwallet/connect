/**
 * Bitcoin wallet connector — message signing via `sats-connect` (Xverse,
 * Leather, Unisat, and any wallet implementing the sats-connect provider RPC).
 *
 * Connect requests the wallet's addresses and prefers a P2WPKH ('bc1q…')
 * payment address (the broadest-compatibility key-path login form). Signing
 * uses `signMessage` with the BIP-322 protocol, which returns a base64
 * signature — a serialized witness stack for segwit/taproot addresses, or a
 * recoverable ECDSA sig for legacy. {@link verifyBitcoin} dispatches on that
 * shape, so the proof here carries the address *type* in `extra.addressType`
 * and scheme `bip322`.
 */
import Wallet, {
  AddressPurpose,
  MessageSigningProtocols,
  type Address,
} from 'sats-connect';
import type {
  Account,
  LoginChallenge,
  SignedProof,
  WalletConnector,
  WalletInfo,
} from '../types.js';
import { buildSiwxMessage } from '../caip122.js';

/** sats-connect addressType → the hint string {@link verifyBitcoin} expects. */
type BtcAddressTypeHint = 'p2pkh' | 'p2wpkh' | 'p2tr';

function toAddressTypeHint(addressType: string): BtcAddressTypeHint | null {
  if (addressType === 'p2pkh' || addressType === 'p2wpkh' || addressType === 'p2tr') {
    return addressType;
  }
  return null;
}

/**
 * Choose the address to sign with. Order of preference:
 *   1. P2WPKH payment ('bc1q…')   — widest wallet + verifier support
 *   2. P2TR payment/ordinals      — taproot key-path
 *   3. P2PKH                      — legacy
 * Returns the chosen entry plus its verifier address-type hint.
 */
function chooseAddress(addresses: readonly Address[]): { addr: Address; hint: BtcAddressTypeHint } | null {
  const ranked: BtcAddressTypeHint[] = ['p2wpkh', 'p2tr', 'p2pkh'];
  for (const want of ranked) {
    const found = addresses.find((a) => toAddressTypeHint(a.addressType) === want);
    if (found) return { addr: found, hint: want };
  }
  return null;
}

export class BitcoinConnector implements WalletConnector {
  readonly chain = 'bitcoin' as const;

  #address: string | null = null;
  #addressType: BtcAddressTypeHint | null = null;
  #walletId = 'sats-connect';

  /**
   * sats-connect resolves the concrete wallet at request time (it shows its own
   * provider picker), so discovery here advertises the aggregate provider.
   */
  async available(): Promise<WalletInfo[]> {
    if (typeof window === 'undefined') return [];
    return [
      {
        id: 'sats-connect',
        name: 'Bitcoin Wallet (Xverse / Leather / Unisat)',
        chain: this.chain,
        installed: true,
      },
    ];
  }

  /**
   * Connect and pick a signing address. `walletId` is forwarded to sats-connect
   * as the provider id when given; otherwise its built-in picker is used.
   */
  async connect(walletId?: string): Promise<Account> {
    if (typeof window === 'undefined') {
      throw new Error('bitcoin: no window — connectors are browser-only');
    }
    if (walletId != null) this.#walletId = walletId;

    const res = await Wallet.request('getAddresses', {
      purposes: [AddressPurpose.Payment, AddressPurpose.Ordinals],
      message: 'Connect to sign in',
    });
    if (res.status !== 'success') {
      throw new Error(`bitcoin: getAddresses failed (${res.error?.message ?? 'rejected'})`);
    }

    const chosen = chooseAddress(res.result.addresses);
    if (!chosen) throw new Error('bitcoin: wallet returned no usable address');

    this.#address = chosen.addr.address;
    this.#addressType = chosen.hint;

    return {
      chain: this.chain,
      address: chosen.addr.address,
      publicKey: chosen.addr.publicKey,
      walletId: this.#walletId,
    };
  }

  /**
   * Render the CAIP-122 message and have the wallet sign it (BIP-322).
   * Produces a `bip322` proof carrying `extra.addressType` so the verifier
   * derives the correct address form.
   */
  async signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof> {
    if (!this.#address || !this.#addressType) {
      throw new Error('bitcoin: not connected — call connect() first');
    }
    const message = buildSiwxMessage({
      challenge,
      address: account.address,
      chain: this.chain,
    });

    const res = await Wallet.request('signMessage', {
      address: account.address,
      message,
      protocol: MessageSigningProtocols.BIP322,
    });
    if (res.status !== 'success') {
      throw new Error(`bitcoin: signMessage failed (${res.error?.message ?? 'rejected'})`);
    }

    return {
      chain: this.chain,
      scheme: 'bip322',
      address: account.address,
      message,
      signature: res.result.signature, // base64
      extra: { addressType: this.#addressType },
    };
  }

  async disconnect(): Promise<void> {
    try {
      await Wallet.disconnect();
    } catch {
      // sats-connect throws if no session; ignore on teardown.
    } finally {
      this.#address = null;
      this.#addressType = null;
    }
  }
}
