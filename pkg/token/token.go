// Package token provides the attp token builder and parser.
package token

import "time"

// ProtocolVersion is the current attp protocol version.
const ProtocolVersion = "1.0"

// InlineThreshold is the size in bytes below which payloads are inlined.
const InlineThreshold = 4096

// Token is the top-level attp token envelope.
type Token struct {
	ATTP        string         `json:"attp"`
	ID          string         `json:"id"`
	CreatedAt   string         `json:"created_at"`
	Provenance  Provenance     `json:"provenance"`
	Repo        Repo           `json:"repo"`
	Sensitivity Sensitivity    `json:"sensitivity"`
	Payloads    []Payload      `json:"payloads"`
	Requests    []Request      `json:"requests,omitempty"`
	Decisions   []Decision     `json:"decisions,omitempty"`
	Extensions  map[string]any `json:"extensions,omitempty"`
}

// Provenance holds origin and chain-of-custody metadata.
type Provenance struct {
	Origin       Origin                 `json:"origin"`
	Participants map[string]Participant `json:"participants,omitempty"`
	VectorClock  map[string]int         `json:"vector_clock"`
	Chain        []ChainEntry           `json:"chain,omitempty"`
	Sequence     int                    `json:"sequence"`
}

// Origin identifies the agent that produced the token.
type Origin struct {
	AgentID      string   `json:"agent_id"`
	AgentVersion string   `json:"agent_version,omitempty"`
	SessionID    string   `json:"session_id,omitempty"`
	Machine      *Machine `json:"machine,omitempty"`
}

// Machine holds machine identity metadata.
type Machine struct {
	Hostname    string `json:"hostname"`
	TailscaleID string `json:"tailscale_id,omitempty"`
}

// Participant describes a participant in the token exchange.
type Participant struct {
	Role             string `json:"role"`
	VectorClockIndex int    `json:"vector_clock_index"`
}

// ChainEntry is a summary of a previous token in the conversation chain.
type ChainEntry struct {
	TokenID   string `json:"token_id"`
	AgentID   string `json:"agent_id"`
	Machine   string `json:"machine"`
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
}

// Repo captures repository state at token creation time.
type Repo struct {
	URL        string   `json:"url"`
	Branch     string   `json:"branch"`
	Commit     string   `json:"commit"`
	DirtyPaths []string `json:"dirty_paths"`
	MerkleRoot string   `json:"merkle_root"`
}

// Sensitivity holds the exclusion manifest and attestation.
type Sensitivity struct {
	HasExclusions        bool                  `json:"has_exclusions"`
	ExcludedPaths        []string              `json:"excluded_paths"`
	ExclusionAttestation *ExclusionAttestation `json:"exclusion_attestation"`
}

// ExclusionAttestation is a cryptographic proof of excluded paths.
type ExclusionAttestation struct {
	MerkleRoot string `json:"merkle_root"`
	Timestamp  string `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
}

// Payload is a content item, either inlined or referenced.
type Payload struct {
	Mode        string    `json:"mode"`
	Path        string    `json:"path"`
	Role        string    `json:"role,omitempty"`
	Content     string    `json:"content,omitempty"`
	FetchVia    *FetchVia `json:"fetch_via,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Hash        string    `json:"hash,omitempty"`
	SizeBytes   int       `json:"size_bytes,omitempty"`
}

// FetchVia describes how to lazily fetch referenced content.
type FetchVia struct {
	ContentHash string `json:"content_hash"`
	SizeBytes   int    `json:"size_bytes"`
	Tool        string `json:"tool,omitempty"`
}

// Request is a structured work request from sender to receiver.
type Request struct {
	Kind    string         `json:"kind"`
	Summary string         `json:"summary"`
	Params  map[string]any `json:"params,omitempty"`
}

// Decision records a decision the receiver should know about.
type Decision struct {
	Summary   string `json:"summary"`
	Rationale string `json:"rationale,omitempty"`
	DecidedAt string `json:"decided_at"`
}

// PayloadOption configures optional payload fields.
type PayloadOption func(*Payload)

// WithRole sets the semantic role of a payload.
func WithRole(role string) PayloadOption {
	return func(p *Payload) { p.Role = role }
}

// WithContentType sets the MIME type of a payload.
func WithContentType(ct string) PayloadOption {
	return func(p *Payload) { p.ContentType = ct }
}

// WithHash sets the content hash of a payload.
func WithHash(hash string) PayloadOption {
	return func(p *Payload) { p.Hash = hash }
}

// nowFunc is overridable for testing.
var nowFunc = time.Now
