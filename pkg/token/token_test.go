package token

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// frozen time for deterministic tests.
var testTime = time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC)

func init() {
	nowFunc = func() time.Time { return testTime }
}

func validBuilder() *Builder {
	return NewBuilder().
		SetProvenance(
			Origin{AgentID: "claude-code", AgentVersion: "1.0"},
			map[string]Participant{"claude-code": {Role: "author", VectorClockIndex: 1}},
			map[string]int{"claude-code": 1},
			1,
		).
		SetRepo(
			"https://github.com/mistakeknot/attp",
			"main",
			"abc123def456",
			nil,
			"sha256:deadbeef",
		).
		SetSensitivity(false, nil, &ExclusionAttestation{
			MerkleRoot: "sha256:deadbeef",
			Timestamp:  testTime.Format(time.RFC3339),
			Nonce:      "testnonce",
			Signature:  "testsig",
		})
}

func TestBuildAndRoundTrip(t *testing.T) {
	tok, err := validBuilder().
		AddInlinePayload("src/main.go", "package main", WithRole("source"), WithContentType("text/x-go")).
		AddRefPayload("data/large.bin", "blake3:aabbccdd", 10000, WithRole("data")).
		AddRequest("review", "Please review the changes", map[string]any{"scope": "full"}).
		AddDecision("Use blake3 for hashing", "Faster than SHA-256").
		SetExtensions(map[string]any{"demarch.interweave": map[string]any{"version": "1.0"}}).
		Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	// Check top-level fields.
	if tok.ATTP != ProtocolVersion {
		t.Errorf("ATTP = %q, want %q", tok.ATTP, ProtocolVersion)
	}
	if tok.CreatedAt == "" {
		t.Error("CreatedAt is empty")
	}

	// Serialize to JSON.
	data, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	// Parse back.
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if parsed.ID != tok.ID {
		t.Errorf("ID mismatch: got %q, want %q", parsed.ID, tok.ID)
	}
	if parsed.Provenance.Origin.AgentID != "claude-code" {
		t.Errorf("AgentID = %q, want %q", parsed.Provenance.Origin.AgentID, "claude-code")
	}
	if len(parsed.Payloads) != 2 {
		t.Fatalf("Payloads len = %d, want 2", len(parsed.Payloads))
	}
	if parsed.Payloads[0].Mode != "inline" {
		t.Errorf("Payload[0].Mode = %q, want %q", parsed.Payloads[0].Mode, "inline")
	}
	if parsed.Payloads[1].Mode != "ref" {
		t.Errorf("Payload[1].Mode = %q, want %q", parsed.Payloads[1].Mode, "ref")
	}
	if parsed.Payloads[1].FetchVia == nil {
		t.Fatal("Payload[1].FetchVia is nil")
	}
	if parsed.Payloads[1].FetchVia.ContentHash != "blake3:aabbccdd" {
		t.Errorf("FetchVia.ContentHash = %q", parsed.Payloads[1].FetchVia.ContentHash)
	}
	if len(parsed.Requests) != 1 {
		t.Fatalf("Requests len = %d, want 1", len(parsed.Requests))
	}
	if parsed.Requests[0].Kind != "review" {
		t.Errorf("Request.Kind = %q", parsed.Requests[0].Kind)
	}
	if len(parsed.Decisions) != 1 {
		t.Fatalf("Decisions len = %d, want 1", len(parsed.Decisions))
	}
	if parsed.Decisions[0].Summary != "Use blake3 for hashing" {
		t.Errorf("Decision.Summary = %q", parsed.Decisions[0].Summary)
	}
	if parsed.Extensions == nil {
		t.Error("Extensions is nil")
	}
}

func TestPayloadModeDiscrimination(t *testing.T) {
	tok, err := validBuilder().
		AddInlinePayload("a.txt", "hello").
		AddRefPayload("b.bin", "sha256:abc", 5000).
		Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if tok.Payloads[0].Mode != "inline" {
		t.Errorf("expected inline, got %q", tok.Payloads[0].Mode)
	}
	if tok.Payloads[0].Content != "hello" {
		t.Errorf("expected content 'hello', got %q", tok.Payloads[0].Content)
	}
	if tok.Payloads[1].Mode != "ref" {
		t.Errorf("expected ref, got %q", tok.Payloads[1].Mode)
	}
	if tok.Payloads[1].FetchVia == nil {
		t.Error("expected FetchVia on ref payload")
	}
}

func TestAddPayloadAutoThreshold(t *testing.T) {
	small := make([]byte, InlineThreshold-1) // below threshold → inline
	for i := range small {
		small[i] = 'a'
	}
	large := make([]byte, InlineThreshold) // at threshold → ref
	for i := range large {
		large[i] = 'b'
	}

	tok, err := validBuilder().
		AddPayload("small.txt", small).
		AddPayload("large.bin", large).
		Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	if tok.Payloads[0].Mode != "inline" {
		t.Errorf("small payload: expected inline, got %q", tok.Payloads[0].Mode)
	}
	if tok.Payloads[1].Mode != "ref" {
		t.Errorf("large payload: expected ref, got %q", tok.Payloads[1].Mode)
	}
}

func TestRejectMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name:    "missing attp",
			json:    `{"id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[]}`,
			wantErr: "missing required field: attp",
		},
		{
			name:    "missing id",
			json:    `{"attp":"1.0","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[]}`,
			wantErr: "missing required field: id",
		},
		{
			name:    "missing agent_id",
			json:    `{"attp":"1.0","id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[]}`,
			wantErr: "provenance.origin.agent_id",
		},
		{
			name:    "missing repo url",
			json:    `{"attp":"1.0","id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[]}`,
			wantErr: "repo.url",
		},
		{
			name:    "sequence zero",
			json:    `{"attp":"1.0","id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":0},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[]}`,
			wantErr: "sequence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.json))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestRejectUnknownMajorVersion(t *testing.T) {
	j := `{"attp":"2.0","id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[]}`
	_, err := Parse([]byte(j))
	if err == nil {
		t.Fatal("expected error for major version 2")
	}
	if !strings.Contains(err.Error(), "unsupported major version") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAcceptUnknownMinorVersion(t *testing.T) {
	j := `{"attp":"1.99","id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[]}`
	tok, err := Parse([]byte(j))
	if err != nil {
		t.Fatalf("should accept version 1.99, got error: %v", err)
	}
	if tok.ATTP != "1.99" {
		t.Errorf("ATTP = %q, want %q", tok.ATTP, "1.99")
	}
}

func TestGeneratedIDFormat(t *testing.T) {
	b := NewBuilder()
	tok, err := validBuilderFrom(b).Build()
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}

	re := regexp.MustCompile(`^attp_[A-Za-z0-9]{20,}$`)
	if !re.MatchString(tok.ID) {
		t.Errorf("ID %q does not match pattern attp_[A-Za-z0-9]{20,}", tok.ID)
	}
}

func TestIDsAreUnique(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		b := NewBuilder()
		if ids[b.token.ID] {
			t.Fatalf("duplicate ID generated: %s", b.token.ID)
		}
		ids[b.token.ID] = true
	}
}

func TestRejectInvalidPayloadMode(t *testing.T) {
	j := `{"attp":"1.0","id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[{"mode":"unknown","path":"x.txt"}]}`
	_, err := Parse([]byte(j))
	if err == nil {
		t.Fatal("expected error for unknown payload mode")
	}
	if !strings.Contains(err.Error(), "unknown mode") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRejectInlinePayloadWithoutContent(t *testing.T) {
	j := `{"attp":"1.0","id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[{"mode":"inline","path":"x.txt"}]}`
	_, err := Parse([]byte(j))
	if err == nil {
		t.Fatal("expected error for inline payload without content")
	}
	if !strings.Contains(err.Error(), "inline payload must have content") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRejectRefPayloadWithoutFetchVia(t *testing.T) {
	j := `{"attp":"1.0","id":"attp_12345678901234567890","created_at":"2026-01-01T00:00:00Z","provenance":{"origin":{"agent_id":"x"},"vector_clock":{"x":1},"sequence":1},"repo":{"url":"u","branch":"b","commit":"c","dirty_paths":[],"merkle_root":"sha256:x"},"sensitivity":{"has_exclusions":false,"excluded_paths":[],"exclusion_attestation":null},"payloads":[{"mode":"ref","path":"x.txt"}]}`
	_, err := Parse([]byte(j))
	if err == nil {
		t.Fatal("expected error for ref payload without fetch_via")
	}
	if !strings.Contains(err.Error(), "ref payload must have fetch_via") {
		t.Errorf("unexpected error: %v", err)
	}
}

// validBuilderFrom applies standard valid fields to an existing builder.
func validBuilderFrom(b *Builder) *Builder {
	return b.
		SetProvenance(
			Origin{AgentID: "test-agent"},
			nil,
			map[string]int{"test-agent": 1},
			1,
		).
		SetRepo("https://example.com/repo", "main", "abc123", nil, "sha256:000").
		SetSensitivity(false, nil, nil)
}
