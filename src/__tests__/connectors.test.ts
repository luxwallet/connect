/**
 * Connector tests.
 *
 * Two things are exercised without a real wallet or browser:
 *   1. getConnector(chain) returns a connector whose `.chain` matches.
 *   2. EVM + Solana round-trip: a MOCKED injected provider (backed by a real
 *      keypair) signs the CAIP-122 message via the connector's signLogin, and
 *      the resulting SignedProof passes the server-side verifyProof.
 *
 * The other connectors (Bitcoin/TON/XRP) drive third-party SDKs whose wallet
 * handshakes cannot be faithfully mocked headlessly; they are covered by their
 * verifiers' round-trip tests and need a real wallet to exercise end-to-end.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import bs58 from 'bs58';
import { getConnector, allConnectors } from '../connectors.js';
import { EvmConnector } from '../evm/connect.js';
import { SolanaConnector } from '../solana/connect.js';
import { verifyProof } from '../verify.js';
import { newChallenge } from '../nonce.js';
import { CHAINS, type Chain } from '../types.js';
import {
  eip191Digest,
  addressFromPublicKey,
  recoverEvmAddress,
} from '../evm/verify.js';
import { bytesToHex, utf8ToBytes, hexToBytes } from '../bytes.js';

// ── factory ──────────────────────────────────────────────────────────────────

describe('getConnector', () => {
  it('returns a connector whose chain matches, for every chain', () => {
    for (const chain of CHAINS) {
      const c = getConnector(chain);
      expect(c.chain).toBe(chain);
    }
  });

  it('binds the right class per chain', () => {
    expect(getConnector('evm')).toBeInstanceOf(EvmConnector);
    expect(getConnector('solana')).toBeInstanceOf(SolanaConnector);
  });

  it('allConnectors() yields one connector per chain, in canonical order', () => {
    const all = allConnectors();
    expect(all.map((c) => c.chain)).toEqual(CHAINS as Chain[]);
  });
});

// ── shared window shim ───────────────────────────────────────────────────────
// A bare window without addEventListener/dispatchEvent so the EVM connector's
// EIP-6963 discovery short-circuits to the legacy window.ethereum path (fast,
// deterministic — no 300ms announce wait).

const realWindow = (globalThis as Record<string, unknown>).window;

function setWindow(props: Record<string, unknown>): void {
  (globalThis as Record<string, unknown>).window = props;
}

afterEach(() => {
  if (realWindow === undefined) {
    delete (globalThis as Record<string, unknown>).window;
  } else {
    (globalThis as Record<string, unknown>).window = realWindow;
  }
});

// ── EVM mock provider (EIP-1193, real secp256k1 key) ─────────────────────────

function makeEvmProvider() {
  const priv = secp256k1.utils.randomPrivateKey();
  const pub = secp256k1.getPublicKey(priv, false);
  const address = addressFromPublicKey(pub); // lowercased 0x…

  const provider = {
    async request({ method, params }: { method: string; params?: unknown[] }): Promise<unknown> {
      switch (method) {
        case 'eth_requestAccounts':
        case 'eth_accounts':
          return [address];
        case 'eth_chainId':
          return '0x1';
        case 'personal_sign': {
          // viem sends [data, account]; data is the 0x-hex of the UTF-8 message.
          const dataHex = params?.[0] as string;
          const msgBytes = hexToBytes(dataHex);
          const message = new TextDecoder().decode(msgBytes);
          const sig = secp256k1.sign(eip191Digest(message), priv);
          const full = new Uint8Array(65);
          full.set(sig.toCompactRawBytes(), 0);
          full[64] = (sig.recovery ?? 0) + 27;
          return '0x' + bytesToHex(full);
        }
        default:
          throw new Error(`unexpected method ${method}`);
      }
    },
  };
  return { provider, address };
}

describe('EvmConnector round-trip (mocked injected wallet)', () => {
  beforeEach(() => {
    const { provider } = makeEvmProvider();
    setWindow({ ethereum: provider });
  });

  it('connects, signs the CAIP-122 message, and verifyProof accepts it', async () => {
    const c = new EvmConnector();
    const account = await c.connect();
    expect(account.chain).toBe('evm');
    expect(account.address).toMatch(/^0x[0-9a-fA-F]{40}$/);

    const now = 1_700_000_000_000;
    const challenge = newChallenge({
      domain: 'hanzo.id',
      uri: 'https://hanzo.id/login',
      nonce: 'evmNonce123',
      now,
    });
    const proof = await c.signLogin(account, challenge);

    expect(proof.scheme).toBe('secp256k1-eip191');
    expect(proof.chain).toBe('evm');
    // The signature recovers the connected address (the verifier's core check).
    expect(recoverEvmAddress(proof.message, proof.signature)?.toLowerCase()).toBe(
      account.address.toLowerCase(),
    );

    const res = verifyProof(proof, { domain: 'hanzo.id', nonce: 'evmNonce123', now });
    expect(res.ok).toBe(true);
    expect(res.address?.toLowerCase()).toBe(account.address.toLowerCase());
    expect(res.chain).toBe('evm');
  });

  it('available() discovers the injected wallet via the legacy path', async () => {
    const c = new EvmConnector();
    const wallets = await c.available();
    expect(wallets.length).toBe(1);
    expect(wallets[0]?.chain).toBe('evm');
    expect(wallets[0]?.installed).toBe(true);
  });
});

// ── Solana mock provider (real ed25519 key) ──────────────────────────────────

function makeSolanaProvider() {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = bs58.encode(pub);

  const publicKey = {
    toBytes: () => pub,
    toString: () => address,
  };
  const provider = {
    isPhantom: true,
    publicKey,
    async connect() {
      return { publicKey };
    },
    async signMessage(message: Uint8Array, _encoding?: string) {
      return { signature: ed25519.sign(message, priv) };
    },
    async disconnect() {},
  };
  return { provider, address };
}

describe('SolanaConnector round-trip (mocked injected wallet)', () => {
  let expectedAddress: string;

  beforeEach(() => {
    const { provider, address } = makeSolanaProvider();
    expectedAddress = address;
    setWindow({ solana: provider });
  });

  it('connects, signs the CAIP-122 message, and verifyProof accepts it', async () => {
    const c = new SolanaConnector();
    const account = await c.connect();
    expect(account.chain).toBe('solana');
    expect(account.address).toBe(expectedAddress);

    const now = 1_700_000_000_000;
    const challenge = newChallenge({
      domain: 'hanzo.id',
      uri: 'https://hanzo.id/login',
      nonce: 'solNonce4567',
      now,
    });
    const proof = await c.signLogin(account, challenge);

    expect(proof.scheme).toBe('ed25519');
    expect(proof.chain).toBe('solana');
    expect(proof.address).toBe(expectedAddress);

    const res = verifyProof(proof, { domain: 'hanzo.id', nonce: 'solNonce4567', now });
    expect(res.ok).toBe(true);
    expect(res.address).toBe(expectedAddress);
    expect(res.chain).toBe('solana');
  });

  it('handles the bare-Uint8Array signMessage return shape', async () => {
    // Some wallets return the raw signature bytes instead of {signature}.
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    const address = bs58.encode(pub);
    const publicKey = { toBytes: () => pub, toString: () => address };
    setWindow({
      solana: {
        isPhantom: true,
        publicKey,
        connect: async () => ({ publicKey }),
        signMessage: async (m: Uint8Array) => ed25519.sign(m, priv),
      },
    });

    const c = new SolanaConnector();
    const account = await c.connect();
    const now = 1_700_000_000_000;
    const challenge = newChallenge({
      domain: 'hanzo.id',
      uri: 'https://hanzo.id/login',
      nonce: 'solBareSig99',
      now,
    });
    const proof = await c.signLogin(account, challenge);
    expect(verifyProof(proof, { domain: 'hanzo.id', nonce: 'solBareSig99', now }).ok).toBe(true);
  });

  it('rejects a proof whose nonce was tampered after signing', async () => {
    const c = new SolanaConnector();
    const account = await c.connect();
    const now = 1_700_000_000_000;
    const challenge = newChallenge({
      domain: 'hanzo.id',
      uri: 'https://hanzo.id/login',
      nonce: 'solGood0001',
      now,
    });
    const proof = await c.signLogin(account, challenge);
    // Server expects a different nonce → rejected before crypto.
    expect(verifyProof(proof, { domain: 'hanzo.id', nonce: 'solOther0002', now }).reason).toBe(
      'nonce-mismatch',
    );
  });
});

// ── browser-only guard ───────────────────────────────────────────────────────

describe('connectors are browser-only', () => {
  it('EVM connect throws without a window', async () => {
    delete (globalThis as Record<string, unknown>).window;
    await expect(new EvmConnector().connect()).rejects.toThrow(/browser-only/);
  });

  it('Solana connect throws without a window', async () => {
    delete (globalThis as Record<string, unknown>).window;
    await expect(new SolanaConnector().connect()).rejects.toThrow(/browser-only/);
  });
});
