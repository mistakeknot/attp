package safety

import (
	"encoding/json"
	"io"
	"time"

	"github.com/mistakeknot/attp/pkg/token"
)

// AuditEntry is a single JSONL audit record.
type AuditEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	Direction     string    `json:"direction"` // "send" or "receive"
	TokenID       string    `json:"token_id"`
	PeerID        string    `json:"peer_id"`
	FileCount     int       `json:"file_count"`
	ExcludedCount int       `json:"excluded_count"`
	SessionID     string    `json:"session_id,omitempty"`
}

// AuditLog writes JSONL audit entries to an io.Writer.
type AuditLog struct {
	w io.Writer
}

// NewAuditLog creates a new AuditLog that writes to w.
func NewAuditLog(w io.Writer) *AuditLog {
	return &AuditLog{w: w}
}

// Log marshals an AuditEntry to JSON and writes it as a single line.
func (a *AuditLog) Log(entry AuditEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = a.w.Write(data)
	return err
}

// LogSend logs a send-direction audit entry for the given token.
func (a *AuditLog) LogSend(t *token.Token, peerID string) error {
	return a.Log(AuditEntry{
		Timestamp:     time.Now(),
		Direction:     "send",
		TokenID:       t.ID,
		PeerID:        peerID,
		FileCount:     len(t.Payloads),
		ExcludedCount: len(t.Sensitivity.ExcludedPaths),
		SessionID:     t.Provenance.Origin.SessionID,
	})
}

// LogReceive logs a receive-direction audit entry for the given token.
func (a *AuditLog) LogReceive(t *token.Token, peerID string) error {
	return a.Log(AuditEntry{
		Timestamp:     time.Now(),
		Direction:     "receive",
		TokenID:       t.ID,
		PeerID:        peerID,
		FileCount:     len(t.Payloads),
		ExcludedCount: len(t.Sensitivity.ExcludedPaths),
		SessionID:     t.Provenance.Origin.SessionID,
	})
}
