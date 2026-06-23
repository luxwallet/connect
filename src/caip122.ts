/**
 * CAIP-122 "Sign-In-With-X" message — the one canonical login string for every
 * chain. Generalizes EIP-4361 (SIWE) so a Solana / Bitcoin / TON / XRP wallet
 * signs the exact same human-readable assertion an Ethereum wallet does.
 *
 * Spec: https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md
 * (which itself generalizes https://eips.ethereum.org/EIPS/eip-4361)
 *
 * build ∘ parse round-trips. Both are pure — no I/O, no clock — so the Go port
 * for IAM can mirror them byte-for-byte.
 */
import type { Chain, LoginChallenge } from './types.js';

/** Human chain label used on the first line of the message. */
const CHAIN_LABEL: Record<Chain, string> = {
  evm: 'Ethereum',
  solana: 'Solana',
  bitcoin: 'Bitcoin',
  ton: 'TON',
  xrp: 'XRP Ledger',
};

export interface ParsedSiwx {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version?: string;
  chainId?: string;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  resources?: string[];
}

export interface BuildParams {
  challenge: LoginChallenge;
  address: string;
  chain: Chain;
  /** CAIP-2 network id, e.g. 'eip155:1', 'solana:5eykt...'. Optional. */
  chainId?: string;
}

/** Render a {@link LoginChallenge} to the canonical CAIP-122 message string. */
export function buildSiwxMessage(params: BuildParams): string {
  const { challenge: c, address, chain, chainId } = params;
  const label = CHAIN_LABEL[chain];

  const lines: string[] = [];
  lines.push(`${c.domain} wants you to sign in with your ${label} account:`);
  lines.push(address);
  lines.push('');
  // Statement block is optional. When present it sits on its own line between
  // two blank lines (per EIP-4361 ABNF).
  if (c.statement != null && c.statement.length > 0) {
    if (c.statement.includes('\n')) {
      throw new Error('caip122: statement must be a single line');
    }
    lines.push(c.statement);
    lines.push('');
  }
  lines.push(`URI: ${c.uri}`);
  lines.push(`Version: ${c.version ?? '1'}`);
  if (chainId != null) {
    lines.push(`Chain ID: ${chainId}`);
  }
  lines.push(`Nonce: ${c.nonce}`);
  lines.push(`Issued At: ${c.issuedAt}`);
  if (c.expirationTime != null) {
    lines.push(`Expiration Time: ${c.expirationTime}`);
  }
  if (c.notBefore != null) {
    lines.push(`Not Before: ${c.notBefore}`);
  }
  if (c.requestId != null) {
    lines.push(`Request ID: ${c.requestId}`);
  }
  if (c.resources != null && c.resources.length > 0) {
    lines.push('Resources:');
    for (const r of c.resources) {
      lines.push(`- ${r}`);
    }
  }
  return lines.join('\n');
}

const HEADER_RE = /^(?<domain>[^\n]+?) wants you to sign in with your .+ account:$/;
const FIELD_RE = /^(?<key>URI|Version|Chain ID|Nonce|Issued At|Expiration Time|Not Before|Request ID): (?<val>.*)$/;

/** Parse a CAIP-122 message back into its fields. Throws on malformed input. */
export function parseSiwxMessage(message: string): ParsedSiwx {
  const raw = message.split('\n');
  if (raw.length < 2) {
    throw new Error('caip122: message too short');
  }
  const header = HEADER_RE.exec(raw[0] ?? '');
  if (!header?.groups) {
    throw new Error('caip122: malformed header line');
  }
  const domain = header.groups.domain;
  const address = (raw[1] ?? '').trim();
  if (address.length === 0) {
    throw new Error('caip122: missing address line');
  }

  // Everything from line 2 onward: an optional statement block, then fields.
  const out: Partial<ParsedSiwx> = { domain, address };
  const resources: string[] = [];
  let inResources = false;
  let statementParts: string[] = [];
  let sawField = false;

  for (let i = 2; i < raw.length; i++) {
    const line = raw[i] ?? '';
    if (inResources) {
      if (line.startsWith('- ')) {
        resources.push(line.slice(2));
        continue;
      }
      inResources = false;
    }
    if (line === 'Resources:') {
      inResources = true;
      sawField = true;
      continue;
    }
    const f = FIELD_RE.exec(line);
    if (f?.groups) {
      sawField = true;
      const v = f.groups.val;
      switch (f.groups.key) {
        case 'URI': out.uri = v; break;
        case 'Version': out.version = v; break;
        case 'Chain ID': out.chainId = v; break;
        case 'Nonce': out.nonce = v; break;
        case 'Issued At': out.issuedAt = v; break;
        case 'Expiration Time': out.expirationTime = v; break;
        case 'Not Before': out.notBefore = v; break;
        case 'Request ID': out.requestId = v; break;
      }
      continue;
    }
    // Pre-field, non-empty, non-field lines are the statement.
    if (!sawField && line.length > 0) {
      statementParts.push(line);
    }
  }

  if (statementParts.length > 0) {
    out.statement = statementParts.join('\n');
  }
  if (resources.length > 0) {
    out.resources = resources;
  }

  if (out.uri == null || out.nonce == null || out.issuedAt == null) {
    throw new Error('caip122: missing required field (URI / Nonce / Issued At)');
  }
  return out as ParsedSiwx;
}
