/**
 * loginWithWallet — the one client-side login flow.
 *
 * Ties a connector's connect → signLogin into a single call: pick the chain,
 * connect the wallet, sign the server-issued {@link LoginChallenge}, and return
 * the {@link SignedProof}. The caller (or its server) mints the challenge and
 * later verifies the proof with {@link import('./verify.js').verifyProof}.
 *
 *   server: newChallenge() ─► client: loginWithWallet({chain, challenge})
 *           ─► SignedProof ─► server: verifyProof(proof, {domain, nonce})
 *
 * This module imports connectors, so it carries the wallet libs. Keep it out of
 * the server verify path.
 */
import type { Account, Chain, LoginChallenge, SignedProof } from './types.js';
import { getConnector, type ConnectorOptions } from './connectors.js';

export interface LoginWithWalletParams {
  /** Which chain's wallet to authenticate. */
  chain: Chain;
  /** Server-minted challenge to sign (domain, nonce, uri, times). */
  challenge: LoginChallenge;
  /** Specific wallet id to target (else the connector's default). */
  walletId?: string;
  /** Per-chain connector options (e.g. TON manifest URL). */
  options?: ConnectorOptions;
}

export interface LoginResult {
  account: Account;
  proof: SignedProof;
}

/**
 * Connect a wallet on `chain` and sign `challenge`, returning the connected
 * account and the {@link SignedProof}. Throws if no wallet is available or the
 * user rejects; the connector is disconnected on failure to avoid a dangling
 * session.
 */
export async function loginWithWallet(params: LoginWithWalletParams): Promise<LoginResult> {
  const connector = getConnector(params.chain, params.options);
  try {
    const account = await connector.connect(params.walletId);
    const proof = await connector.signLogin(account, params.challenge);
    return { account, proof };
  } catch (err) {
    await connector.disconnect().catch(() => {});
    throw err;
  }
}
