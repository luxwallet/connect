import { describe, it, expect } from 'vitest';
import { buildSiwxMessage, parseSiwxMessage } from '../caip122.js';
import { newChallenge } from '../nonce.js';

describe('CAIP-122 message', () => {
  const now = 1_700_000_000_000; // fixed epoch for determinism

  it('build → parse round-trips all fields', () => {
    const challenge = newChallenge({
      domain: 'hanzo.id',
      uri: 'https://hanzo.id/login',
      statement: 'Sign in to Hanzo.',
      nonce: 'abc12345',
      now,
      ttlSeconds: 600,
      requestId: 'req-1',
      resources: ['https://hanzo.ai/api', 'https://hanzo.chat'],
    });
    const msg = buildSiwxMessage({
      challenge,
      address: '0x1111111111111111111111111111111111111111',
      chain: 'evm',
      chainId: 'eip155:1',
    });
    const p = parseSiwxMessage(msg);
    expect(p.domain).toBe('hanzo.id');
    expect(p.address).toBe('0x1111111111111111111111111111111111111111');
    expect(p.statement).toBe('Sign in to Hanzo.');
    expect(p.uri).toBe('https://hanzo.id/login');
    expect(p.version).toBe('1');
    expect(p.chainId).toBe('eip155:1');
    expect(p.nonce).toBe('abc12345');
    expect(p.issuedAt).toBe(new Date(now).toISOString());
    expect(p.expirationTime).toBe(new Date(now + 600_000).toISOString());
    expect(p.requestId).toBe('req-1');
    expect(p.resources).toEqual(['https://hanzo.ai/api', 'https://hanzo.chat']);
  });

  it('renders the chain label on the header line', () => {
    const c = newChallenge({ domain: 'hanzo.id', uri: 'https://hanzo.id', nonce: 'nonce123', now });
    expect(buildSiwxMessage({ challenge: c, address: 'So1aNa', chain: 'solana' })).toContain(
      'wants you to sign in with your Solana account:',
    );
    expect(buildSiwxMessage({ challenge: c, address: 'bc1q', chain: 'bitcoin' })).toContain(
      'with your Bitcoin account:',
    );
    expect(buildSiwxMessage({ challenge: c, address: 'EQxx', chain: 'ton' })).toContain(
      'with your TON account:',
    );
    expect(buildSiwxMessage({ challenge: c, address: 'rXYZ', chain: 'xrp' })).toContain(
      'with your XRP Ledger account:',
    );
  });

  it('omits optional fields when absent', () => {
    const c = newChallenge({ domain: 'd', uri: 'https://d', nonce: 'nonce123', now });
    const msg = buildSiwxMessage({ challenge: { ...c, expirationTime: undefined }, address: 'a', chain: 'evm' });
    expect(msg).not.toContain('Chain ID:');
    expect(msg).not.toContain('Request ID:');
    expect(msg).not.toContain('Resources:');
  });

  it('rejects a multi-line statement', () => {
    const c = newChallenge({ domain: 'd', uri: 'https://d', nonce: 'nonce123', now, statement: 'a\nb' });
    expect(() => buildSiwxMessage({ challenge: c, address: 'a', chain: 'evm' })).toThrow();
  });

  it('throws on malformed message', () => {
    expect(() => parseSiwxMessage('not a siwx message')).toThrow();
  });
});
