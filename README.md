# attp — Agent Token Transfer Protocol

A protocol for structured bidirectional context transfer between AI coding agents on separate machines.

## What is attp?

attp enables two (or more) people's AI coding agent sessions to collaborate seamlessly — sharing repo state, decisions, file content, and work requests — without shared tmux, screen-sharing, or pasting prose summaries.

The protocol cryptographically enforces sensitivity boundaries: when collaborating on the same repo with asymmetric access (one machine has credentials, PII, or proprietary data that the other cannot see), attp ensures sensitive content never crosses the wire — even accidentally.

## Core Concepts

**Token** — A structured JSON document containing repo state, file content (inline or by reference), decisions, and requests. Self-describing: a receiver with no prior state can parse any valid token.

**Merkle Exclusion Proof** — A flat sorted binary tree (BLAKE3) that cryptographically attests which paths were excluded from a token. Prevents accidental leaks without requiring trust.

**MCP Tools** — 16 tools across 5 groups (Discovery, Token Lifecycle, Content Transfer, Verification, Session Management) that agents use to exchange tokens via the Model Context Protocol.

**Sessions** — Scoped collaboration contexts between agents. Support N participants with per-session sensitivity policies.

## Quick Start

```bash
# Initialize attp in your repo
attp init

# Build a token from current repo state
attp pack

# Verify a received token
attp verify token.json

# Start the MCP server
attp serve

# Push a token to a peer
attp push alice-laptop
```

## Architecture

```
┌─────────────┐     attp token      ┌─────────────┐
│  Agent A    │ ◄──────────────────► │  Agent B    │
│  (MCP srv)  │   Merkle-verified   │  (MCP srv)  │
│             │   sensitivity-safe  │             │
│  .attpignore│                     │  .attpignore│
│  (secrets)  │                     │  (no access)│
└─────────────┘                     └─────────────┘
```

## Protocol Version

Current: `1.0`

Versioning uses `major.minor` strings. Minor versions add fields (old consumers ignore unknowns). Major versions are breaking changes.

## License

Apache-2.0
