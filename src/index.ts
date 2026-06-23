/**
 * @luxwallet/connect — multi-chain wallet connect + Sign-In-With-X.
 *
 * Public surface. One vocabulary ({@link Chain}, {@link SignedProof}), one
 * canonical login message (CAIP-122), one verifier ({@link verifyProof}).
 *
 * MIT licensed, zero GPL — clean of the Uniswap-derived bones that stay
 * quarantined in luxfi/exchange.
 */
export type {
  Chain,
  SignatureScheme,
  Account,
  LoginChallenge,
  SignedProof,
  VerifyExpectation,
  VerifyResult,
  WalletConnector,
  WalletInfo,
} from './types.js';
export { CHAINS } from './types.js';

export { buildSiwxMessage, parseSiwxMessage } from './caip122.js';
export type { ParsedSiwx, BuildParams } from './caip122.js';

export { generateNonce, newChallenge } from './nonce.js';

export { verifyProof } from './verify.js';

// Per-chain primitives (useful standalone; the connectors build on them).
export { verifyEvm, recoverEvmAddress, eip191Digest } from './evm/verify.js';
export { verifySolana } from './solana/verify.js';
export { verifyTon } from './ton/verify.js';
export { verifyBitcoin } from './bitcoin/verify.js';
export { verifyXrp } from './xrp/verify.js';

// Browser wallet connectors + the high-level login flow. These import the
// wallet libraries (viem, sats-connect, @tonconnect/sdk, @crossmarkio/sdk);
// the server verify path above pulls NONE of them.
export {
  getConnector,
  allConnectors,
  EvmConnector,
  SolanaConnector,
  BitcoinConnector,
  TonConnector,
  XrpConnector,
} from './connectors.js';
export type { ConnectorOptions, TonConnectorOptions } from './connectors.js';
export { loginWithWallet } from './login.js';
export type { LoginWithWalletParams, LoginResult } from './login.js';
