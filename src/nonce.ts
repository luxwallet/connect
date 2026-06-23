/**
 * Single-use login nonces. The server mints one per challenge, stores it, and
 * burns it on verify so a captured proof cannot be replayed.
 */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Cryptographically-random alphanumeric nonce (default 16 chars, ~95 bits). */
export function generateNonce(length = 16): string {
  if (length < 8) {
    throw new Error('nonce: length must be >= 8 (CAIP-122 minimum)');
  }
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += ALPHABET[bytes[i]! % ALPHABET.length];
  }
  return out;
}

/** Build a {@link import('./types.js').LoginChallenge} with sane defaults. */
export function newChallenge(opts: {
  domain: string;
  uri: string;
  statement?: string;
  nonce?: string;
  /** TTL in seconds for the expirationTime field. Default 600 (10 min). */
  ttlSeconds?: number;
  /** Epoch ms for "now"; injectable for tests. */
  now?: number;
  requestId?: string;
  resources?: string[];
}) {
  const nowMs = opts.now ?? Date.now();
  const issuedAt = new Date(nowMs).toISOString();
  const ttl = opts.ttlSeconds ?? 600;
  const expirationTime = new Date(nowMs + ttl * 1000).toISOString();
  return {
    domain: opts.domain,
    uri: opts.uri,
    statement: opts.statement,
    nonce: opts.nonce ?? generateNonce(),
    issuedAt,
    expirationTime,
    version: '1',
    requestId: opts.requestId,
    resources: opts.resources,
  };
}
