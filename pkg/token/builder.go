package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/zeebo/blake3"
)

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Builder constructs attp tokens with a fluent API.
type Builder struct {
	token Token
	err   error
}

// NewBuilder creates a new token builder with version and generated ID.
func NewBuilder() *Builder {
	id, err := generateID()
	b := &Builder{
		token: Token{
			ATTP:     ProtocolVersion,
			ID:       id,
			Payloads: []Payload{},
		},
		err: err,
	}
	return b
}

// SetRepo sets the repository state snapshot.
func (b *Builder) SetRepo(url, branch, commit string, dirtyPaths []string, merkleRoot string) *Builder {
	if dirtyPaths == nil {
		dirtyPaths = []string{}
	}
	b.token.Repo = Repo{
		URL:        url,
		Branch:     branch,
		Commit:     commit,
		DirtyPaths: dirtyPaths,
		MerkleRoot: merkleRoot,
	}
	return b
}

// AddInlinePayload adds an inline payload with the given content.
func (b *Builder) AddInlinePayload(path, content string, opts ...PayloadOption) *Builder {
	p := Payload{
		Mode:      "inline",
		Path:      path,
		Content:   content,
		SizeBytes: len(content),
		Hash:      contentHash([]byte(content)),
	}
	for _, opt := range opts {
		opt(&p)
	}
	b.token.Payloads = append(b.token.Payloads, p)
	return b
}

// AddRefPayload adds a ref payload for lazy fetch.
func (b *Builder) AddRefPayload(path, contentHash string, sizeBytes int, opts ...PayloadOption) *Builder {
	p := Payload{
		Mode:      "ref",
		Path:      path,
		Hash:      contentHash,
		SizeBytes: sizeBytes,
		FetchVia: &FetchVia{
			ContentHash: contentHash,
			SizeBytes:   sizeBytes,
		},
	}
	for _, opt := range opts {
		opt(&p)
	}
	b.token.Payloads = append(b.token.Payloads, p)
	return b
}

// AddPayload auto-chooses inline vs ref based on InlineThreshold.
func (b *Builder) AddPayload(path string, content []byte) *Builder {
	if len(content) < InlineThreshold {
		return b.AddInlinePayload(path, string(content))
	}
	hash := contentHash(content)
	return b.AddRefPayload(path, hash, len(content))
}

// AddRequest adds a structured work request.
func (b *Builder) AddRequest(kind, summary string, params map[string]any) *Builder {
	b.token.Requests = append(b.token.Requests, Request{
		Kind:    kind,
		Summary: summary,
		Params:  params,
	})
	return b
}

// AddDecision adds a decision record.
func (b *Builder) AddDecision(summary, rationale string) *Builder {
	b.token.Decisions = append(b.token.Decisions, Decision{
		Summary:   summary,
		Rationale: rationale,
		DecidedAt: nowFunc().UTC().Format(time.RFC3339),
	})
	return b
}

// SetSensitivity sets the exclusion manifest.
func (b *Builder) SetSensitivity(hasExclusions bool, excludedPaths []string, attestation *ExclusionAttestation) *Builder {
	if excludedPaths == nil {
		excludedPaths = []string{}
	}
	b.token.Sensitivity = Sensitivity{
		HasExclusions:        hasExclusions,
		ExcludedPaths:        excludedPaths,
		ExclusionAttestation: attestation,
	}
	return b
}

// SetProvenance sets provenance metadata.
func (b *Builder) SetProvenance(origin Origin, participants map[string]Participant, vectorClock map[string]int, sequence int) *Builder {
	b.token.Provenance = Provenance{
		Origin:       origin,
		Participants: participants,
		VectorClock:  vectorClock,
		Sequence:     sequence,
	}
	return b
}

// SetExtensions sets the extensions map.
func (b *Builder) SetExtensions(extensions map[string]any) *Builder {
	b.token.Extensions = extensions
	return b
}

// Build validates and returns the completed token.
func (b *Builder) Build() (*Token, error) {
	if b.err != nil {
		return nil, fmt.Errorf("builder error: %w", b.err)
	}

	b.token.CreatedAt = nowFunc().UTC().Format(time.RFC3339)

	if b.token.ATTP == "" {
		return nil, fmt.Errorf("attp version is required")
	}
	if b.token.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if b.token.Provenance.Origin.AgentID == "" {
		return nil, fmt.Errorf("provenance.origin.agent_id is required")
	}
	if b.token.Provenance.VectorClock == nil {
		return nil, fmt.Errorf("provenance.vector_clock is required")
	}
	if b.token.Provenance.Sequence < 1 {
		return nil, fmt.Errorf("provenance.sequence must be >= 1")
	}
	if b.token.Repo.URL == "" {
		return nil, fmt.Errorf("repo.url is required")
	}
	if b.token.Repo.Branch == "" {
		return nil, fmt.Errorf("repo.branch is required")
	}
	if b.token.Repo.Commit == "" {
		return nil, fmt.Errorf("repo.commit is required")
	}
	if b.token.Repo.MerkleRoot == "" {
		return nil, fmt.Errorf("repo.merkle_root is required")
	}
	if b.token.Repo.DirtyPaths == nil {
		b.token.Repo.DirtyPaths = []string{}
	}
	if b.token.Sensitivity.ExcludedPaths == nil {
		b.token.Sensitivity.ExcludedPaths = []string{}
	}

	t := b.token
	return &t, nil
}

// generateID creates a token ID: attp_ + 20 random base62 characters.
func generateID() (string, error) {
	var sb strings.Builder
	sb.WriteString("attp_")
	max := big.NewInt(int64(len(base62Chars)))
	for i := 0; i < 20; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		sb.WriteByte(base62Chars[n.Int64()])
	}
	return sb.String(), nil
}

// contentHash computes a blake3 hash and returns it in algorithm:hex format.
func contentHash(data []byte) string {
	h := blake3.Sum256(data)
	return "blake3:" + hex.EncodeToString(h[:])
}
