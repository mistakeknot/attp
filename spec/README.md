# attp Token Specification

Version: **1.0** | Schema: [token-schema.json](token-schema.json) | Draft: 2020-12

## Overview

An attp token is a self-describing JSON document that carries repository context between agents on different machines. A consumer with no prior state can parse any valid token and extract: what repo state it describes, what content is included, what content was excluded, who produced it, and how to fetch anything not inlined.

## Versioning

The `attp` field is a **major.minor string** (e.g., `"1.0"`, never a bare number).

### Rules

1. **Minor bump** (1.0 to 1.1): New optional fields added. Old consumers MUST ignore unknown fields and MUST preserve them when re-serializing (ignore-and-forward). New consumers SHOULD NOT require new fields.
2. **Major bump** (1.x to 2.0): Breaking change (field removed, type changed, new required field). Consumers MUST reject tokens with an unrecognized major version.
3. **Unknown field policy**: ignore and forward. A consumer encountering a field it does not recognize MUST preserve it in any re-serialization. It MUST NOT reject the token.
4. The `attp` field is always a string, never a JSON number. This avoids floating-point precision issues and permits future suffixes like `"2.0-rc1"`.

### Compatibility matrix

| Consumer | Token | Result |
|---|---|---|
| 1.0 | 1.0 | Full support |
| 1.0 | 1.3 | Works; unknown fields ignored and forwarded |
| 1.0 | 2.0 | REJECT (unknown major version) |
| 2.0 | 1.0 | MAY support (backward compat at implementor discretion) |

### Validation logic

```
Parse attp field as "MAJOR.MINOR"
If MAJOR != supported_major -> reject with "unsupported attp version"
If MINOR > supported_minor -> warn "newer minor version, some fields may be ignored"
Proceed with parsing, skipping unknown fields
```

## Top-Level Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `attp` | string | yes | Protocol version (major.minor). |
| `id` | string | yes | Globally unique token ID. Format: `attp_` + 20+ base62 chars. |
| `created_at` | string | yes | ISO 8601 timestamp with timezone. When the token was assembled. |
| `provenance` | object | yes | Origin, participants, vector clock, and chain-of-custody. |
| `repo` | object | yes | Repository state snapshot at token creation time. |
| `sensitivity` | object | yes | Exclusion manifest and cryptographic attestation. |
| `payloads` | array | yes | Content items (inline or reference). May be empty `[]`. |
| `requests` | array | no | Structured work requests from sender to receiver. |
| `decisions` | array | no | Decisions made by sender that receiver should know about. |
| `extensions` | object | no | Namespaced extension data (e.g., `"demarch.interweave"`). |

## Provenance

The `provenance` object tracks who created the token, who has participated in the exchange, and the causal history.

- **`origin`**: Identifies the agent that produced this token. Contains `agent_id` (required), plus optional `agent_version`, `session_id`, and `machine` (object with required `hostname` and optional `tailscale_id`).
- **`participants`**: Object map where keys are agent IDs. Each value has `role` (e.g., `"author"`, `"reviewer"`) and `vector_clock_index` (integer, the agent's clock value when they last touched the token).
- **`vector_clock`**: Object map of agent_id to integer. Enables causal ordering across multiple agents without synchronized wall clocks. Each agent increments its own entry before producing a token.
- **`chain`**: Array of previous token summaries in chronological order. Each entry has `token_id`, `agent_id`, `machine` (string), `timestamp`, and `action` (one of `"initiated"`, `"responded"`, `"forwarded"`). Append-only; producers MAY truncate to the last 20 entries for long conversations.
- **`sequence`**: Integer starting at 1, monotonically increasing within a conversation. Enables ordering even when timestamps are clock-skewed.

## Repository State (`repo`)

Captures the exact state of the repository when the token was created.

- **`url`**: Canonical repo URL (used for identity, not cloning).
- **`branch`**: Current branch name.
- **`commit`**: Full commit SHA.
- **`dirty_paths`**: Array of repo-relative paths with uncommitted changes (may be empty).
- **`merkle_root`**: Content-addressed root hash of the repo tree. Format: `algorithm:hex` (e.g., `sha256:a1b2c3d4...`).

## Sensitivity Model

The `sensitivity` object declares what was excluded from the token and provides cryptographic proof of the exclusion. The token is self-describing: a receiver knows what was excluded without running Merkle proof verification.

- **`has_exclusions`** (boolean): Quick check. `false` means nothing was excluded; `excluded_paths` will be empty.
- **`excluded_paths`** (string array): Repo-relative paths that were excluded. Directories end with `/`. Path names themselves are not considered sensitive in attp's threat model (the protocol prevents accidental content leaks, not path enumeration).
- **`exclusion_attestation`**: Cryptographic proof that the listed paths were actually excluded.
  - `merkle_root`: Root hash of the full repo tree (including excluded paths). Format: `algorithm:hex`.
  - `timestamp`: When the attestation was generated (ISO 8601).
  - `nonce`: Random value preventing attestation replay across tokens.
  - `signature`: Cryptographic signature over the attestation fields. Verification method depends on transport.

## Payload Modes

Every payload item has a `mode` field that is either `"inline"` or `"ref"`. There is no implicit mode and no third option. The explicit discriminator prevents ambiguity (e.g., distinguishing an inline empty file from a reference).

### Inline mode

The file content is carried directly in the token. Recommended for files under 4 KiB.

Required fields: `mode` (`"inline"`), `path`, `content`.
Optional fields: `role`, `content_type`, `hash`, `size_bytes`.

```json
{
  "mode": "inline",
  "path": "src/auth/types.go",
  "role": "source",
  "content": "package auth\n\ntype User struct {\n\tID    string\n\tEmail string\n}\n",
  "content_type": "text/x-go",
  "hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "size_bytes": 67
}
```

### Ref mode

The content is not inlined; the consumer fetches it lazily via an MCP tool. Recommended for files over 4 KiB and all binary files.

Required fields: `mode` (`"ref"`), `path`, `fetch_via` (object with `content_hash` and `size_bytes`).
Optional fields: `role`, `content_type`, `hash`, `size_bytes`, `fetch_via.tool`.

```json
{
  "mode": "ref",
  "path": "src/auth/middleware.go",
  "role": "source",
  "content_type": "text/x-go",
  "hash": "sha256:4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
  "size_bytes": 12847,
  "fetch_via": {
    "content_hash": "sha256:4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
    "size_bytes": 12847,
    "tool": "attp_fetch_file"
  }
}
```

The `fetch_via.content_hash` serves as a cache key and integrity check after fetch. The `fetch_via.size_bytes` lets the consumer decide whether to fetch before committing bandwidth.

## Requests

Structured asks from sender to receiver. Each request has:

- **`kind`**: One of `file_content`, `interface_contract`, `decision`, `review`, `custom`.
- **`summary`**: Human-readable description of the request.
- **`params`** (optional): Object with request-specific parameters.

## Decisions

Records of choices the sender made that affect the receiver's work. Each decision has:

- **`summary`** (required): What was decided.
- **`rationale`** (optional): Why.
- **`decided_at`** (required): ISO 8601 timestamp.

## Extensions

The `extensions` object holds namespaced data for framework-specific integrations. Keys use reverse-domain naming (e.g., `"demarch.interweave"`, `"cursor.workspace"`). No registry is required; the key is the producer's namespace.

Rules:
1. Extensions are always optional. Unknown extensions MUST be ignored.
2. Extensions MUST NOT duplicate base fields.
3. A valid token with no extensions omits the field entirely.

## Complete Example Token

The following token validates against the schema in `token-schema.json`.

```json
{
  "attp": "1.0",
  "id": "attp_7kR9mX2pLq4nB8vW3jY5",
  "created_at": "2026-03-19T14:30:00Z",
  "provenance": {
    "origin": {
      "agent_id": "claude-code",
      "agent_version": "1.42.0",
      "session_id": "sess_abc123",
      "machine": {
        "hostname": "alice-mbp",
        "tailscale_id": "alice-laptop.tailnet"
      }
    },
    "participants": {
      "claude-code": {
        "role": "author",
        "vector_clock_index": 1
      }
    },
    "vector_clock": {
      "claude-code": 1
    },
    "chain": [],
    "sequence": 1
  },
  "repo": {
    "url": "git@github.com:acme/backend.git",
    "branch": "main",
    "commit": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
    "dirty_paths": ["src/auth/middleware.go"],
    "merkle_root": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "sensitivity": {
    "has_exclusions": true,
    "excluded_paths": [
      "credentials/",
      ".env",
      "data/pii/"
    ],
    "exclusion_attestation": {
      "merkle_root": "sha256:a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
      "timestamp": "2026-03-19T14:29:58Z",
      "nonce": "r4nd0mN0nc3V4lu3",
      "signature": "ed25519:base64signaturedata..."
    }
  },
  "payloads": [
    {
      "mode": "inline",
      "path": "src/auth/types.go",
      "role": "source",
      "content_type": "text/x-go",
      "content": "package auth\n\ntype User struct {\n\tID    string\n\tEmail string\n}\n",
      "hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "size_bytes": 67
    },
    {
      "mode": "ref",
      "path": "src/auth/middleware.go",
      "role": "source",
      "content_type": "text/x-go",
      "hash": "sha256:4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
      "size_bytes": 12847,
      "fetch_via": {
        "content_hash": "sha256:4e1243bd22c66e76c2ba9eddc1f91394e57f9f83",
        "size_bytes": 12847,
        "tool": "attp_fetch_file"
      }
    }
  ],
  "requests": [
    {
      "kind": "review",
      "summary": "Review auth middleware changes for timing attack vectors in the comparison logic",
      "params": {
        "paths": ["src/auth/middleware.go"],
        "priority": "high"
      }
    }
  ],
  "decisions": [
    {
      "summary": "Using bcrypt instead of argon2 for password hashing",
      "rationale": "argon2 Go bindings require CGO; bcrypt is pure Go and sufficient for our scale",
      "decided_at": "2026-03-19T14:25:00Z"
    }
  ],
  "extensions": {
    "demarch.interweave": {
      "bead_id": "Demarch-e1mi",
      "sprint_id": "sprint-42"
    }
  }
}
```
