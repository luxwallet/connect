/**
 * Minimal CBOR (RFC 8949) — exactly the subset COSE_Sign1 / COSE_Key need, no
 * deps. Inline, pure, fail-closed — the same self-contained-codec style as
 * src/bitcoin/bech32.ts. Keeping it inline keeps the verify core free of any
 * third-party CBOR dependency (and therefore free of any copyleft surprise in a
 * transitive tree).
 *
 * Decoder: handles the major types a CIP-8 COSE object uses —
 *   0 unsigned int, 1 negative int, 2 byte string, 3 text string,
 *   4 array, 5 map, 7 simple (false/true/null) — with definite lengths only
 *   (every wallet emits definite-length COSE). Indefinite lengths, tags,
 *   floats, and bignums are rejected (return failure) — fail closed.
 *
 * Encoder: emits the canonical (definite-length, smallest-int) encoding for the
 * one structure the verifier builds: the COSE `Sig_structure`
 *   [ "Signature1", bstr(protected), bstr(external_aad), bstr(payload) ].
 * That is: text string, byte string, array — nothing else — so the encoder is
 * deliberately tiny and only supports those.
 *
 * Mirrors go/walletconnect/cardano_cbor.go byte-for-byte.
 */

/** A decoded CBOR value. Maps preserve key order and use the decoded key value. */
export type CborValue =
  | number
  | bigint
  | Uint8Array
  | string
  | boolean
  | null
  | CborValue[]
  | CborMap;

/** A CBOR map. Keys can be ints or strings (the only key types COSE uses). */
export type CborMap = Map<number | bigint | string, CborValue>;

/** Thrown internally on any malformed/unsupported input; callers fail closed. */
class CborError extends Error {}

/**
 * Maximum CBOR nesting depth. A COSE_Sign1 / COSE_Key is shallow (array →
 * map/bstr → value, depth ≤ 3); this bounds the recursive decoder so a crafted
 * deeply-nested input (`81 81 81 …`) can't exhaust the stack — a DoS that would
 * otherwise depend solely on the signature-size cap. 16 is far above any real
 * COSE object. Mirrors maxCborDepth in cardano_cbor.go.
 */
const MAX_CBOR_DEPTH = 16;

interface Cursor {
  readonly buf: Uint8Array;
  pos: number;
}

function readUint(c: Cursor, n: number): number | bigint {
  if (c.pos + n > c.buf.length) throw new CborError('truncated');
  let v = 0n;
  for (let i = 0; i < n; i++) {
    v = (v << 8n) | BigInt(c.buf[c.pos++]!);
  }
  // Return a number when it fits exactly in a JS safe integer; else a bigint.
  return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
}

/** Read the (major type, argument) of the next CBOR head. */
function readHead(c: Cursor): { major: number; arg: number | bigint } {
  if (c.pos >= c.buf.length) throw new CborError('truncated head');
  const ib = c.buf[c.pos++]!;
  const major = ib >> 5;
  const ai = ib & 0x1f;
  if (ai < 24) return { major, arg: ai };
  if (ai === 24) return { major, arg: readUint(c, 1) };
  if (ai === 25) return { major, arg: readUint(c, 2) };
  if (ai === 26) return { major, arg: readUint(c, 4) };
  if (ai === 27) return { major, arg: readUint(c, 8) };
  // 28..30 reserved; 31 indefinite — unsupported by this COSE subset.
  throw new CborError('unsupported additional info ' + ai);
}

function asLen(arg: number | bigint): number {
  const n = typeof arg === 'bigint' ? Number(arg) : arg;
  if (!Number.isSafeInteger(n) || n < 0) throw new CborError('bad length');
  return n;
}

function decodeValue(c: Cursor, depth: number): CborValue {
  if (depth > MAX_CBOR_DEPTH) throw new CborError('nesting too deep');
  const { major, arg } = readHead(c);
  switch (major) {
    case 0: // unsigned int
      return arg;
    case 1: // negative int: -1 - arg
      return typeof arg === 'bigint' ? -1n - arg : -1 - arg;
    case 2: { // byte string
      const len = asLen(arg);
      if (c.pos + len > c.buf.length) throw new CborError('truncated bstr');
      const out = c.buf.subarray(c.pos, c.pos + len);
      c.pos += len;
      return Uint8Array.from(out);
    }
    case 3: { // text string (UTF-8)
      const len = asLen(arg);
      if (c.pos + len > c.buf.length) throw new CborError('truncated tstr');
      const out = c.buf.subarray(c.pos, c.pos + len);
      c.pos += len;
      return new TextDecoder('utf-8', { fatal: true }).decode(out);
    }
    case 4: { // array
      const len = asLen(arg);
      // Guard against a huge declared length on a tiny buffer: each element
      // consumes ≥1 byte, so len can't exceed the bytes remaining.
      if (len > c.buf.length - c.pos) throw new CborError('array longer than buffer');
      const arr: CborValue[] = [];
      for (let i = 0; i < len; i++) arr.push(decodeValue(c, depth + 1));
      return arr;
    }
    case 5: { // map
      const len = asLen(arg);
      // Each entry consumes ≥2 bytes (key + value); reject an impossible length.
      if (len > (c.buf.length - c.pos)) throw new CborError('map longer than buffer');
      const m: CborMap = new Map();
      for (let i = 0; i < len; i++) {
        const k = decodeValue(c, depth + 1);
        const v = decodeValue(c, depth + 1);
        if (typeof k !== 'number' && typeof k !== 'bigint' && typeof k !== 'string') {
          throw new CborError('unsupported map key type');
        }
        m.set(k, v);
      }
      return m;
    }
    case 7: // simple values
      if (arg === 20) return false;
      if (arg === 21) return true;
      if (arg === 22) return null;
      throw new CborError('unsupported simple value ' + String(arg));
    default:
      throw new CborError('unsupported major type ' + major);
  }
}

/** Decode a single top-level CBOR value. Returns null on any malformation. */
export function cborDecode(buf: Uint8Array): CborValue | null {
  try {
    const c: Cursor = { buf, pos: 0 };
    const v = decodeValue(c, 0);
    // Trailing bytes after a complete value are a malformation — reject.
    if (c.pos !== buf.length) return null;
    return v;
  } catch {
    return null;
  }
}

// ── encoder (only what the Sig_structure needs) ─────────────────────────────

function encodeHead(major: number, n: number): number[] {
  const mt = major << 5;
  if (n < 24) return [mt | n];
  if (n < 0x100) return [mt | 24, n & 0xff];
  if (n < 0x10000) return [mt | 25, (n >> 8) & 0xff, n & 0xff];
  if (n < 0x100000000)
    return [mt | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  // 64-bit length (payloads are never this large, but be exact).
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  return [
    mt | 27,
    (hi >>> 24) & 0xff, (hi >> 16) & 0xff, (hi >> 8) & 0xff, hi & 0xff,
    (lo >>> 24) & 0xff, (lo >> 16) & 0xff, (lo >> 8) & 0xff, lo & 0xff,
  ];
}

function encodeText(s: string): number[] {
  const bytes = new TextEncoder().encode(s);
  return encodeHead(3, bytes.length).concat(Array.from(bytes));
}

function encodeBytes(b: Uint8Array): number[] {
  return encodeHead(2, b.length).concat(Array.from(b));
}

/**
 * Build the COSE `Sig_structure` for a COSE_Sign1:
 *   [ "Signature1", bstr(protectedSerialized), bstr(externalAad), bstr(payload) ]
 * `protectedSerialized` is the raw (already-CBOR-encoded) protected-headers
 * byte string taken verbatim from COSE_Sign1[0]; `externalAad` is empty.
 */
export function buildSigStructure(
  protectedSerialized: Uint8Array,
  externalAad: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  const out: number[] = [];
  out.push(...encodeHead(4, 4)); // array(4)
  out.push(...encodeText('Signature1'));
  out.push(...encodeBytes(protectedSerialized));
  out.push(...encodeBytes(externalAad));
  out.push(...encodeBytes(payload));
  return Uint8Array.from(out);
}
