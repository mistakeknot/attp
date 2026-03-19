// Package server implements the attp MCP server with stdio JSON-RPC transport.
package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/mistakeknot/attp/pkg/safety"
	"github.com/mistakeknot/attp/pkg/token"
)

// Config configures the attp MCP server.
type Config struct {
	PeerID          string
	DisplayName     string
	ListenAddr      string
	ProtocolVersion string
	Features        []string
	Confirmer       safety.Confirmer
	AuditLog        *safety.AuditLog
}

// Server is an in-memory attp MCP server.
type Server struct {
	mu       sync.Mutex
	config   Config
	peers    map[string]*PeerInfo
	sessions map[string]*Session
	inbox    []*InboxEntry
	outbox   map[string]*OutboxEntry
	policy   *Policy
}

// PeerInfo describes a known peer.
type PeerInfo struct {
	PeerID          string   `json:"peer_id"`
	DisplayName     string   `json:"display_name"`
	Endpoint        string   `json:"endpoint"`
	ProtocolVersion string   `json:"protocol_version"`
	Features        []string `json:"features"`
	Status          string   `json:"status"`
	LastSeen        time.Time
	ActiveSession   string `json:"active_session"`
}

// Session is an active collaboration session.
type Session struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	PeerID         string    `json:"peer_id"`
	RepoIdentifier string    `json:"repo_identifier"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	TokensSent     int       `json:"tokens_sent"`
	TokensReceived int       `json:"tokens_received"`
	LastActivity   time.Time `json:"last_activity"`
}

// InboxEntry is a received token.
type InboxEntry struct {
	Token        *token.Token
	ReceivedAt   time.Time
	SessionID    string
	Quarantined  *safety.QuarantinedToken
	Acknowledged bool
	Disposition  string
	AckedAt      *time.Time
	FromPeer     string
}

// OutboxEntry is a sent token with delivery status.
type OutboxEntry struct {
	Token       *token.Token
	SentAt      time.Time
	PeerID      string
	SessionID   string
	Status      string
	AckedAt     *time.Time
	Disposition string
	Notes       string
}

// Policy holds content sharing policy.
type Policy struct {
	ExcludedPatterns         []string `json:"excluded_patterns"`
	SensitivitySources       []string `json:"sensitivity_sources"`
	AutoInlineThresholdBytes int      `json:"auto_inline_threshold_bytes"`
	AllowedContentTypes      []string `json:"allowed_content_types"`
	MaxTokenBytes            int      `json:"max_token_bytes"`
}

// New creates a new Server with the given config.
func New(cfg Config) *Server {
	if cfg.ProtocolVersion == "" {
		cfg.ProtocolVersion = token.ProtocolVersion
	}
	if cfg.Features == nil {
		cfg.Features = []string{}
	}
	return &Server{
		config:   cfg,
		peers:    make(map[string]*PeerInfo),
		sessions: make(map[string]*Session),
		inbox:    nil,
		outbox:   make(map[string]*OutboxEntry),
		policy: &Policy{
			ExcludedPatterns:         []string{},
			SensitivitySources:       []string{"gitignore"},
			AutoInlineThresholdBytes: 4096,
			AllowedContentTypes:      []string{"diff", "ast", "file", "tree"},
			MaxTokenBytes:            1048576,
		},
	}
}

// toolError creates a simple error with a type tag for MCP error responses.
type toolError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (e *toolError) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func newToolError(errType, msg string) error {
	return &toolError{Type: errType, Message: msg}
}
