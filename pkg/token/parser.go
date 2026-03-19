package token

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Parse unmarshals JSON data into a Token and validates it.
func Parse(data []byte) (*Token, error) {
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing token JSON: %w", err)
	}
	if err := Validate(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Validate checks a token for required fields, version format, and payload consistency.
func Validate(t *Token) error {
	// Version check.
	if t.ATTP == "" {
		return fmt.Errorf("missing required field: attp")
	}
	major, _, err := parseVersion(t.ATTP)
	if err != nil {
		return fmt.Errorf("invalid attp version %q: %w", t.ATTP, err)
	}
	if major != 1 {
		return fmt.Errorf("unsupported major version %d (expected 1)", major)
	}

	// Required top-level fields.
	if t.ID == "" {
		return fmt.Errorf("missing required field: id")
	}
	if t.CreatedAt == "" {
		return fmt.Errorf("missing required field: created_at")
	}

	// Provenance required fields.
	if t.Provenance.Origin.AgentID == "" {
		return fmt.Errorf("missing required field: provenance.origin.agent_id")
	}
	if t.Provenance.VectorClock == nil {
		return fmt.Errorf("missing required field: provenance.vector_clock")
	}
	if t.Provenance.Sequence < 1 {
		return fmt.Errorf("provenance.sequence must be >= 1")
	}

	// Repo required fields.
	if t.Repo.URL == "" {
		return fmt.Errorf("missing required field: repo.url")
	}
	if t.Repo.Branch == "" {
		return fmt.Errorf("missing required field: repo.branch")
	}
	if t.Repo.Commit == "" {
		return fmt.Errorf("missing required field: repo.commit")
	}
	if t.Repo.MerkleRoot == "" {
		return fmt.Errorf("missing required field: repo.merkle_root")
	}

	// Payload consistency.
	for i, p := range t.Payloads {
		switch p.Mode {
		case "inline":
			if p.Content == "" {
				return fmt.Errorf("payload[%d]: inline payload must have content", i)
			}
		case "ref":
			if p.FetchVia == nil {
				return fmt.Errorf("payload[%d]: ref payload must have fetch_via", i)
			}
		default:
			return fmt.Errorf("payload[%d]: unknown mode %q", i, p.Mode)
		}
		if p.Path == "" {
			return fmt.Errorf("payload[%d]: path is required", i)
		}
	}

	return nil
}

// parseVersion splits "major.minor" into integer parts.
func parseVersion(v string) (major, minor int, err error) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("version must be major.minor")
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major version: %w", err)
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor version: %w", err)
	}
	return major, minor, nil
}
