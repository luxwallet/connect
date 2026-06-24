// Package walletconnect is the Go port of @luxwallet/connect's login verifier.
//
// It mirrors the TypeScript src/ byte-for-byte so Hanzo IAM (Casdoor, Go)
// verifies wallet logins identically to verifyProof: same CAIP-122 message
// parse, same domain/nonce/time checks, same EIP-191 digest, same ed25519
// check. The two implementations must stay in lockstep.
package walletconnect

import (
	"fmt"
	"regexp"
	"strings"
)

// Chain is a supported chain family. Values, not places — namespaced by this
// type. Mirrors the TS `Chain` union.
type Chain string

const (
	ChainEVM      Chain = "evm"
	ChainSolana   Chain = "solana"
	ChainBitcoin  Chain = "bitcoin"
	ChainTON      Chain = "ton"
	ChainXRP      Chain = "xrp"
	ChainPolkadot Chain = "polkadot"
)

// chainLabel is the human chain label used on the first line of the message.
// Mirrors the TS CHAIN_LABEL record exactly.
var chainLabel = map[Chain]string{
	ChainEVM:      "Ethereum",
	ChainSolana:   "Solana",
	ChainBitcoin:  "Bitcoin",
	ChainTON:      "TON",
	ChainXRP:      "XRP Ledger",
	ChainPolkadot: "Polkadot",
}

// ParsedSiwx is the result of parsing a CAIP-122 message. Optional fields use
// pointers so absence (TS `undefined`) is distinguishable from empty string.
type ParsedSiwx struct {
	Domain         string
	Address        string
	Statement      *string
	URI            string
	Version        *string
	ChainID        *string
	Nonce          string
	IssuedAt       string
	ExpirationTime *string
	NotBefore      *string
	RequestID      *string
	Resources      []string
}

// LoginChallenge mirrors the TS LoginChallenge: the fields a server asks a
// wallet to sign. Optional fields are pointers (TS `undefined`).
type LoginChallenge struct {
	Domain         string
	URI            string
	Statement      *string
	Nonce          string
	IssuedAt       string
	ExpirationTime *string
	NotBefore      *string
	RequestID      *string
	Version        *string
	Resources      []string
}

// BuildParams mirrors the TS BuildParams for buildSiwxMessage.
type BuildParams struct {
	Challenge LoginChallenge
	Address   string
	Chain     Chain
	// ChainID is the CAIP-2 network id, e.g. "eip155:1". nil to omit.
	ChainID *string
}

// BuildSiwxMessage renders a LoginChallenge to the canonical CAIP-122 message
// string. Mirrors the TS buildSiwxMessage line-for-line. Returns an error if a
// statement contains a newline (TS throws).
func BuildSiwxMessage(p BuildParams) (string, error) {
	c := p.Challenge
	label := chainLabel[p.Chain]

	lines := make([]string, 0, 16)
	lines = append(lines, fmt.Sprintf("%s wants you to sign in with your %s account:", c.Domain, label))
	lines = append(lines, p.Address)
	lines = append(lines, "")
	// Statement block is optional. When present it sits on its own line between
	// two blank lines (per EIP-4361 ABNF).
	if c.Statement != nil && len(*c.Statement) > 0 {
		if strings.Contains(*c.Statement, "\n") {
			return "", fmt.Errorf("caip122: statement must be a single line")
		}
		lines = append(lines, *c.Statement)
		lines = append(lines, "")
	}
	lines = append(lines, "URI: "+c.URI)
	version := "1"
	if c.Version != nil {
		version = *c.Version
	}
	lines = append(lines, "Version: "+version)
	if p.ChainID != nil {
		lines = append(lines, "Chain ID: "+*p.ChainID)
	}
	lines = append(lines, "Nonce: "+c.Nonce)
	lines = append(lines, "Issued At: "+c.IssuedAt)
	if c.ExpirationTime != nil {
		lines = append(lines, "Expiration Time: "+*c.ExpirationTime)
	}
	if c.NotBefore != nil {
		lines = append(lines, "Not Before: "+*c.NotBefore)
	}
	if c.RequestID != nil {
		lines = append(lines, "Request ID: "+*c.RequestID)
	}
	if len(c.Resources) > 0 {
		lines = append(lines, "Resources:")
		for _, r := range c.Resources {
			lines = append(lines, "- "+r)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// headerRE mirrors the TS HEADER_RE. The domain is non-greedy (`+?`) so it
// stops at the first " wants you to sign in with your " occurrence. Go's RE2
// has no lazy/greedy backtracking difference that matters here because the
// suffix is anchored with `$`, but we keep `+?` for fidelity with the TS source.
var headerRE = regexp.MustCompile(`^(.+?) wants you to sign in with your .+ account:$`)

// fieldRE mirrors the TS FIELD_RE: an exact, ordered set of recognised keys.
var fieldRE = regexp.MustCompile(`^(URI|Version|Chain ID|Nonce|Issued At|Expiration Time|Not Before|Request ID): (.*)$`)

func strPtr(s string) *string { return &s }

// ParseSiwxMessage parses a CAIP-122 message back into its fields. Returns an
// error on malformed input. Mirrors the TS parseSiwxMessage exactly, including
// the statement/resources block handling and the required-field check.
func ParseSiwxMessage(message string) (ParsedSiwx, error) {
	var out ParsedSiwx
	raw := strings.Split(message, "\n")
	if len(raw) < 2 {
		return out, fmt.Errorf("caip122: message too short")
	}
	header := headerRE.FindStringSubmatch(raw[0])
	if header == nil {
		return out, fmt.Errorf("caip122: malformed header line")
	}
	out.Domain = header[1]
	out.Address = strings.TrimSpace(raw[1])
	if len(out.Address) == 0 {
		return out, fmt.Errorf("caip122: missing address line")
	}

	// Everything from line 2 onward: an optional statement block, then fields.
	var resources []string
	inResources := false
	var statementParts []string
	sawField := false

	for i := 2; i < len(raw); i++ {
		line := raw[i]
		if inResources {
			if strings.HasPrefix(line, "- ") {
				resources = append(resources, line[2:])
				continue
			}
			inResources = false
		}
		if line == "Resources:" {
			inResources = true
			sawField = true
			continue
		}
		if f := fieldRE.FindStringSubmatch(line); f != nil {
			sawField = true
			key, v := f[1], f[2]
			switch key {
			case "URI":
				out.URI = v
			case "Version":
				out.Version = strPtr(v)
			case "Chain ID":
				out.ChainID = strPtr(v)
			case "Nonce":
				out.Nonce = v
			case "Issued At":
				out.IssuedAt = v
			case "Expiration Time":
				out.ExpirationTime = strPtr(v)
			case "Not Before":
				out.NotBefore = strPtr(v)
			case "Request ID":
				out.RequestID = strPtr(v)
			}
			continue
		}
		// Pre-field, non-empty, non-field lines are the statement.
		if !sawField && len(line) > 0 {
			statementParts = append(statementParts, line)
		}
	}

	if len(statementParts) > 0 {
		out.Statement = strPtr(strings.Join(statementParts, "\n"))
	}
	if len(resources) > 0 {
		out.Resources = resources
	}

	// TS checks: out.uri == null || out.nonce == null || out.issuedAt == null.
	// A field that never appeared is the zero value "" here; the TS message
	// always renders these three, and parse must reject a message missing any.
	if out.URI == "" || out.Nonce == "" || out.IssuedAt == "" {
		return out, fmt.Errorf("caip122: missing required field (URI / Nonce / Issued At)")
	}
	return out, nil
}
