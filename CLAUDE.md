# attp — Agent Token Transfer Protocol

Standalone protocol for structured bidirectional context transfer between AI coding agents on separate machines. Framework-agnostic — no Demarch dependencies.

## Quick Commands

```bash
go build ./...          # Build all packages
go test ./...           # Run all tests
go test -race ./...     # Run tests with race detector
go build -o attp ./cmd/attp  # Build CLI binary
```

## Design Decisions (Do Not Re-Ask)

- **Versioning:** `major.minor` string (e.g., `"1.0"`), not semver. Unknown fields: ignore-and-forward. Major bump = breaking change.
- **Merkle tree:** Flat sorted binary tree, BLAKE3 keyed mode. NOT directory-mirroring. Full rehash for v1 (incremental deferred to v2).
- **Payloads:** Discriminated union via explicit `mode` field (`"inline"` | `"ref"`). Inline threshold: 4 KiB.
- **Sensitivity:** Content-addressed exclusion proofs. Paths excluded from Merkle tree entirely (not just content).
- **Multi-party:** Schema designed for N agents (participants map, vector clocks). V1 ships bilateral only.
- **Transport:** Framework-agnostic MCP tools. No Tailscale/Demarch identifiers in tool contracts.
- **Safety:** Human confirmation required before every token send. Received content quarantined.
- **Signing:** Ed25519 for exclusion attestations. Machine-local keypairs.
- **Go version:** 1.24
- **No CGO.** Pure Go dependencies only.
