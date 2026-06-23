/**
 * XRP (XRP Ledger) wallet connector — Crossmark (`@crossmarkio/sdk`, MIT).
 *
 * Crossmark's `signInAndWait(hex)` performs a sign-in that also signs the hex
 * bytes we pass, returning the account's r-address, its 33-byte public key
 * (hex, with the XRPL family tag — `0xED` for ed25519, `0x02/0x03` for
 * secp256k1), and the signature. {@link verifyXrp} digests the CAIP-122 message
 * the same way XRPL does and checks the signature under that key, then binds
 * the key to the r-address.
 *
 * The signing input must be the CAIP-122 message bytes: we pass
 * `hex(utf8(message))` to the wallet and set `proof.message` to the same
 * string, so the verifier's `utf8ToBytes(proof.message)` digest matches what
 * the wallet signed. The scheme is chosen from the public key's family tag.
 *
 * GemWallet is intentionally NOT wired: its only client (`@gemwallet/api`) ships
 * under a custom dual license that requires GemWallet's permission for
 * public/commercial use — incompatible with this package's MIT/Apache/ISC-only
 * rule. Crossmark covers both XRPL key types, so the XRP path stays complete.
 */
import sdk from '@crossmarkio/sdk';
import type {
  Account,
  LoginChallenge,
  SignedProof,
  SignatureScheme,
  WalletConnector,
  WalletInfo,
} from '../types.js';
import { buildSiwxMessage } from '../caip122.js';
import { utf8ToBytes, bytesToHex } from '../bytes.js';

/** XRPL public-key family tag → signature scheme. */
function schemeForPublicKey(publicKeyHex: string): SignatureScheme {
  const tag = publicKeyHex.slice(0, 2).toLowerCase();
  return tag === 'ed' ? 'ed25519-xrpl' : 'secp256k1-xrpl';
}

export class XrpConnector implements WalletConnector {
  readonly chain = 'xrp' as const;

  #publicKey: string | null = null;

  /** Crossmark is the supported XRP wallet; report it when installed. */
  async available(): Promise<WalletInfo[]> {
    if (typeof window === 'undefined') return [];
    const installed = sdk.sync.isInstalled() === true;
    return [
      {
        id: 'crossmark',
        name: 'Crossmark',
        chain: this.chain,
        installed,
        downloadUrl: installed ? undefined : 'https://crossmark.io',
      },
    ];
  }

  /**
   * Connect via Crossmark sign-in. We do a bare sign-in here to capture the
   * address + public key; the actual login signature is produced in signLogin.
   */
  async connect(walletId?: string): Promise<Account> {
    if (typeof window === 'undefined') {
      throw new Error('xrp: no window — connectors are browser-only');
    }
    if (walletId != null && walletId !== 'crossmark') {
      throw new Error(`xrp: unsupported wallet '${walletId}' (only 'crossmark')`);
    }

    const res = await sdk.async.signInAndWait();
    const data = res?.response?.data;
    if (!data?.address || !data?.publicKey) {
      throw new Error('xrp: Crossmark sign-in returned no address/public key');
    }

    this.#publicKey = data.publicKey;

    return {
      chain: this.chain,
      address: data.address,
      publicKey: data.publicKey,
      walletId: 'crossmark',
    };
  }

  /**
   * Render the CAIP-122 message, have Crossmark sign its UTF-8 bytes (passed as
   * hex), and assemble a proof under the key's scheme. The signature lands in
   * the sign-in response's `signature` field when a hex challenge is supplied.
   */
  async signLogin(account: Account, challenge: LoginChallenge): Promise<SignedProof> {
    if (!this.#publicKey) throw new Error('xrp: not connected — call connect() first');

    const message = buildSiwxMessage({
      challenge,
      address: account.address,
      chain: this.chain,
    });
    const hex = bytesToHex(utf8ToBytes(message));

    const res = await sdk.async.signInAndWait(hex);
    const data = res?.response?.data;
    if (!data?.signature) {
      throw new Error('xrp: Crossmark did not return a signature');
    }
    // The public key may refine on the signing response; prefer it if present.
    const publicKey = data.publicKey ?? this.#publicKey;

    return {
      chain: this.chain,
      scheme: schemeForPublicKey(publicKey),
      address: account.address,
      publicKey,
      message,
      signature: data.signature,
    };
  }

  async disconnect(): Promise<void> {
    this.#publicKey = null;
  }
}
