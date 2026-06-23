/**
 * Browser wallet connectors — the client side of @luxwallet/connect.
 *
 * One factory, one vocabulary: {@link getConnector} returns the
 * {@link WalletConnector} for a {@link Chain}; every connector produces a
 * {@link SignedProof} the matching server-side verifier accepts.
 *
 * IMPORTANT: this module (and everything it imports) pulls the wallet libraries
 * (viem, sats-connect, @tonconnect/sdk, @crossmarkio/sdk). The server verify
 * path (`@luxwallet/connect/verify`) imports NONE of this — keep it that way.
 */
import type { Chain, WalletConnector } from './types.js';
import { EvmConnector } from './evm/connect.js';
import { SolanaConnector } from './solana/connect.js';
import { BitcoinConnector } from './bitcoin/connect.js';
import { TonConnector, type TonConnectorOptions } from './ton/connect.js';
import { XrpConnector } from './xrp/connect.js';

export { EvmConnector } from './evm/connect.js';
export { SolanaConnector } from './solana/connect.js';
export { BitcoinConnector } from './bitcoin/connect.js';
export { TonConnector, type TonConnectorOptions } from './ton/connect.js';
export { XrpConnector } from './xrp/connect.js';

/** Per-chain construction options. Only TON needs one (its dApp manifest URL). */
export interface ConnectorOptions {
  ton?: TonConnectorOptions;
}

/** Build the connector for a chain. Pure construction — no I/O, no window touch. */
export function getConnector(chain: Chain, options: ConnectorOptions = {}): WalletConnector {
  switch (chain) {
    case 'evm':
      return new EvmConnector();
    case 'solana':
      return new SolanaConnector();
    case 'bitcoin':
      return new BitcoinConnector();
    case 'ton':
      return new TonConnector(options.ton);
    case 'xrp':
      return new XrpConnector();
    default: {
      // Exhaustiveness: a new Chain must be handled here.
      const _never: never = chain;
      throw new Error(`no connector for chain '${String(_never)}'`);
    }
  }
}

/** One connector per supported chain, in canonical order. */
export function allConnectors(options: ConnectorOptions = {}): WalletConnector[] {
  return [
    getConnector('evm', options),
    getConnector('solana', options),
    getConnector('bitcoin', options),
    getConnector('ton', options),
    getConnector('xrp', options),
  ];
}
