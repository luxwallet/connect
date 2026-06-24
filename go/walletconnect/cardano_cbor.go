package walletconnect

// Minimal CBOR (RFC 8949) — exactly the subset COSE_Sign1 / COSE_Key need, no
// deps. Inline, pure, fail-closed — the same self-contained-codec style as
// cardano_bech32.go / bitcoin_bech32.go. Mirrors src/cardano/cbor.ts
// byte-for-byte.
//
// Decoder handles definite-length: 0 uint, 1 negint, 2 bstr, 3 tstr, 4 array,
// 5 map, 7 simple (false/true/null). Indefinite lengths, tags, floats and
// bignums are rejected — fail closed. Encoder emits only the canonical
// Sig_structure [ "Signature1", bstr(protected), bstr(aad), bstr(payload) ].
//
// Every identifier is cbor-prefixed: this flat package is shared by all chains.

import (
	"errors"
	"unicode/utf8"
)

var errCbor = errors.New("cbor: malformed")

// maxCborDepth bounds the recursive decoder. A COSE_Sign1 / COSE_Key is shallow
// (array → map/bstr → value, depth ≤ 3); this rejects a crafted deeply-nested
// input (e.g. 0x81 0x81 0x81 …) so it can't exhaust the goroutine stack — a DoS
// that Go's recover() does NOT catch (a stack overflow is fatal). 16 is far
// above any real COSE object. Mirrors MAX_CBOR_DEPTH in src/cardano/cbor.ts.
const maxCborDepth = 16

// cborValue is a decoded CBOR value. Maps use cborMap; integers are int64;
// byte/text strings are []byte/string; arrays are []cborValue.
type cborValue any

// cborMapEntry preserves a single map key/value (order preserved). Keys are
// int64 or string — the only key types COSE uses.
type cborMapEntry struct {
	keyInt int64
	keyStr string
	isStr  bool
	value  cborValue
}

// cborMap is an ordered COSE map. Lookups are linear (COSE maps are tiny).
type cborMap struct {
	entries []cborMapEntry
}

func (m *cborMap) getInt(k int64) (cborValue, bool) {
	for _, e := range m.entries {
		if !e.isStr && e.keyInt == k {
			return e.value, true
		}
	}
	return nil, false
}

func (m *cborMap) getStr(k string) (cborValue, bool) {
	for _, e := range m.entries {
		if e.isStr && e.keyStr == k {
			return e.value, true
		}
	}
	return nil, false
}

type cborCursor struct {
	buf []byte
	pos int
}

// readUint reads an n-byte big-endian unsigned integer as int64. CBOR uses up
// to 8-byte arguments; COSE never exceeds int64, and we reject values that do.
func (c *cborCursor) readUint(n int) (int64, error) {
	if c.pos+n > len(c.buf) {
		return 0, errCbor
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = (v << 8) | uint64(c.buf[c.pos])
		c.pos++
	}
	if v > 0x7fffffffffffffff { // > int64 max
		return 0, errCbor
	}
	return int64(v), nil
}

// readHead reads the next (major type, argument) head.
func (c *cborCursor) readHead() (major int, arg int64, err error) {
	if c.pos >= len(c.buf) {
		return 0, 0, errCbor
	}
	ib := c.buf[c.pos]
	c.pos++
	major = int(ib >> 5)
	ai := int(ib & 0x1f)
	switch {
	case ai < 24:
		return major, int64(ai), nil
	case ai == 24:
		arg, err = c.readUint(1)
	case ai == 25:
		arg, err = c.readUint(2)
	case ai == 26:
		arg, err = c.readUint(4)
	case ai == 27:
		arg, err = c.readUint(8)
	default: // 28..31 reserved / indefinite — unsupported
		return 0, 0, errCbor
	}
	return major, arg, err
}

func (c *cborCursor) decodeValue(depth int) (cborValue, error) {
	if depth > maxCborDepth {
		return nil, errCbor
	}
	major, arg, err := c.readHead()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0: // unsigned int
		return arg, nil
	case 1: // negative int: -1 - arg
		return -1 - arg, nil
	case 2: // byte string
		if arg < 0 || c.pos+int(arg) > len(c.buf) {
			return nil, errCbor
		}
		out := make([]byte, arg)
		copy(out, c.buf[c.pos:c.pos+int(arg)])
		c.pos += int(arg)
		return out, nil
	case 3: // text string (UTF-8)
		if arg < 0 || c.pos+int(arg) > len(c.buf) {
			return nil, errCbor
		}
		b := c.buf[c.pos : c.pos+int(arg)]
		if !utf8.Valid(b) {
			return nil, errCbor
		}
		s := string(b)
		c.pos += int(arg)
		return s, nil
	case 4: // array
		// Each element consumes >=1 byte, so a declared length above the bytes
		// remaining is impossible — reject before allocating.
		if arg < 0 || arg > int64(len(c.buf)-c.pos) {
			return nil, errCbor
		}
		arr := make([]cborValue, 0, arg)
		for i := int64(0); i < arg; i++ {
			v, e := c.decodeValue(depth + 1)
			if e != nil {
				return nil, e
			}
			arr = append(arr, v)
		}
		return arr, nil
	case 5: // map
		// Each entry consumes >=2 bytes (key + value); reject an impossible len.
		if arg < 0 || arg > int64(len(c.buf)-c.pos) {
			return nil, errCbor
		}
		m := &cborMap{entries: make([]cborMapEntry, 0, arg)}
		for i := int64(0); i < arg; i++ {
			k, e := c.decodeValue(depth + 1)
			if e != nil {
				return nil, e
			}
			v, e2 := c.decodeValue(depth + 1)
			if e2 != nil {
				return nil, e2
			}
			switch kv := k.(type) {
			case int64:
				m.entries = append(m.entries, cborMapEntry{keyInt: kv, value: v})
			case string:
				m.entries = append(m.entries, cborMapEntry{keyStr: kv, isStr: true, value: v})
			default:
				return nil, errCbor
			}
		}
		return m, nil
	case 7: // simple values
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil //nolint:nilnil // CBOR null is a legitimate value
		default:
			return nil, errCbor
		}
	default:
		return nil, errCbor
	}
}

// cborDecode decodes a single top-level CBOR value, rejecting trailing bytes.
// Returns ok=false on any malformation. Mirrors the TS cborDecode.
func cborDecode(buf []byte) (cborValue, bool) {
	c := &cborCursor{buf: buf}
	v, err := c.decodeValue(0)
	if err != nil {
		return nil, false
	}
	if c.pos != len(buf) {
		return nil, false
	}
	return v, true
}

// ── encoder (only what the Sig_structure needs) ─────────────────────────────

func cborEncodeHead(major int, n int) []byte {
	mt := byte(major << 5)
	switch {
	case n < 24:
		return []byte{mt | byte(n)}
	case n < 0x100:
		return []byte{mt | 24, byte(n)}
	case n < 0x10000:
		return []byte{mt | 25, byte(n >> 8), byte(n)}
	case n < 0x100000000:
		return []byte{mt | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{
			mt | 27,
			byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
	}
}

func cborEncodeText(s string) []byte {
	return append(cborEncodeHead(3, len(s)), []byte(s)...)
}

func cborEncodeBytes(b []byte) []byte {
	return append(cborEncodeHead(2, len(b)), b...)
}

// cborBuildSigStructure builds the COSE Sig_structure for a COSE_Sign1:
//
//	[ "Signature1", bstr(protectedSerialized), bstr(externalAad), bstr(payload) ]
//
// protectedSerialized is the raw protected-headers byte string from
// COSE_Sign1[0]; externalAad is empty. Mirrors the TS buildSigStructure.
func cborBuildSigStructure(protectedSerialized, externalAad, payload []byte) []byte {
	out := cborEncodeHead(4, 4) // array(4)
	out = append(out, cborEncodeText("Signature1")...)
	out = append(out, cborEncodeBytes(protectedSerialized)...)
	out = append(out, cborEncodeBytes(externalAad)...)
	out = append(out, cborEncodeBytes(payload)...)
	return out
}
