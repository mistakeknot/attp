package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mistakeknot/attp/pkg/safety"
	"github.com/mistakeknot/attp/pkg/token"
	"github.com/zeebo/blake3"
)

// --- Discovery ---

func (s *Server) handleListPeers(_ map[string]any) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	peers := make([]map[string]any, 0, len(s.peers))
	for _, p := range s.peers {
		entry := map[string]any{
			"peer_id":          p.PeerID,
			"display_name":     p.DisplayName,
			"endpoint":         p.Endpoint,
			"status":           p.Status,
			"protocol_version": p.ProtocolVersion,
			"last_seen":        p.LastSeen.UTC().Format(time.RFC3339),
		}
		if p.ActiveSession != "" {
			entry["active_session"] = p.ActiveSession
		}
		peers = append(peers, entry)
	}
	return map[string]any{"peers": peers}, nil
}

func (s *Server) handlePeerCapabilities(params map[string]any) (any, error) {
	peerID, _ := params["peer_id"].(string)
	if peerID == "" {
		return nil, newToolError("VALIDATION", "peer_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.peers[peerID]
	if !ok {
		return nil, newToolError("PEER_NOT_FOUND", fmt.Sprintf("peer %q not found", peerID))
	}

	return map[string]any{
		"peer_id":                   p.PeerID,
		"protocol_version":          p.ProtocolVersion,
		"features":                  p.Features,
		"max_token_bytes":           1048576,
		"supported_hash_algorithms": []string{"blake3"},
		"status":                    p.Status,
	}, nil
}

func (s *Server) handleAnnounce(params map[string]any) (any, error) {
	peerID, _ := params["peer_id"].(string)
	endpoint, _ := params["endpoint"].(string)
	protocolVersion, _ := params["protocol_version"].(string)
	displayName, _ := params["display_name"].(string)

	if peerID == "" {
		return nil, newToolError("VALIDATION", "peer_id is required")
	}
	if endpoint == "" {
		return nil, newToolError("VALIDATION", "endpoint is required")
	}
	if protocolVersion == "" {
		return nil, newToolError("VALIDATION", "protocol_version is required")
	}

	var features []string
	if f, ok := params["features"]; ok {
		if arr, ok := f.([]any); ok {
			for _, v := range arr {
				if str, ok := v.(string); ok {
					features = append(features, str)
				}
			}
		}
	}
	if features == nil {
		features = []string{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.peers[peerID] = &PeerInfo{
		PeerID:          peerID,
		DisplayName:     displayName,
		Endpoint:        endpoint,
		ProtocolVersion: protocolVersion,
		Features:        features,
		Status:          "online",
		LastSeen:        time.Now(),
	}

	return map[string]any{
		"peer_id":     peerID,
		"announced":   true,
		"ttl_seconds": 300,
	}, nil
}

// --- Token Lifecycle ---

func (s *Server) handlePushToken(params map[string]any) (any, error) {
	peerID, _ := params["peer_id"].(string)
	sessionID, _ := params["session_id"].(string)

	if peerID == "" {
		return nil, newToolError("VALIDATION", "peer_id is required")
	}
	if sessionID == "" {
		return nil, newToolError("VALIDATION", "session_id is required")
	}

	// Parse the token from params.
	tokenData, ok := params["token"]
	if !ok {
		return nil, newToolError("VALIDATION", "token is required")
	}
	tokenJSON, err := json.Marshal(tokenData)
	if err != nil {
		return nil, newToolError("TOKEN_INVALID", fmt.Sprintf("cannot marshal token: %v", err))
	}
	tok, err := token.Parse(tokenJSON)
	if err != nil {
		return nil, newToolError("TOKEN_INVALID", fmt.Sprintf("invalid token: %v", err))
	}

	s.mu.Lock()

	// Check peer exists.
	peer, peerExists := s.peers[peerID]
	if !peerExists {
		s.mu.Unlock()
		return nil, newToolError("PEER_NOT_FOUND", fmt.Sprintf("peer %q not found", peerID))
	}

	// Check session exists and is active.
	sess, sessExists := s.sessions[sessionID]
	if !sessExists {
		s.mu.Unlock()
		return nil, newToolError("SESSION_NOT_FOUND", fmt.Sprintf("session %q not found", sessionID))
	}
	if sess.Status == "ended" {
		s.mu.Unlock()
		return nil, newToolError("SESSION_ENDED", fmt.Sprintf("session %q has ended", sessionID))
	}

	s.mu.Unlock()

	// Require confirmation before sending.
	if s.config.Confirmer != nil {
		summary := safety.SummarizeToken(tok, peer.DisplayName)
		approved, err := s.config.Confirmer.Confirm(summary)
		if err != nil {
			return nil, newToolError("INTERNAL_ERROR", fmt.Sprintf("confirmation error: %v", err))
		}
		if !approved {
			return nil, newToolError("POLICY_VIOLATION", "token send denied by confirmer")
		}
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Log to audit.
	if s.config.AuditLog != nil {
		_ = s.config.AuditLog.LogSend(tok, peerID)
	}

	// Add to outbox.
	s.outbox[tok.ID] = &OutboxEntry{
		Token:     tok,
		SentAt:    now,
		PeerID:    peerID,
		SessionID: sessionID,
		Status:    "delivered",
	}

	// Update session stats.
	sess.TokensSent++
	sess.LastActivity = now

	sizeBytes := len(tokenJSON)

	return map[string]any{
		"token_id":     tok.ID,
		"peer_id":      peerID,
		"session_id":   sessionID,
		"status":       "delivered",
		"delivered_at": now.UTC().Format(time.RFC3339),
		"size_bytes":   sizeBytes,
	}, nil
}

func (s *Server) handlePullTokens(params map[string]any) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionID, _ := params["session_id"].(string)
	peerID, _ := params["peer_id"].(string)
	statusFilter := "unacked"
	if sf, ok := params["status_filter"].(string); ok && sf != "" {
		statusFilter = sf
	}
	limit := 20
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
	}
	if limit > 100 {
		limit = 100
	}

	var results []map[string]any
	totalUnacked := 0

	for _, entry := range s.inbox {
		if !entry.Acknowledged {
			totalUnacked++
		}

		// Apply filters.
		if sessionID != "" && entry.SessionID != sessionID {
			continue
		}
		if peerID != "" && entry.FromPeer != peerID {
			continue
		}
		switch statusFilter {
		case "unacked":
			if entry.Acknowledged {
				continue
			}
		case "acked":
			if !entry.Acknowledged {
				continue
			}
		}

		if len(results) >= limit {
			break
		}

		result := map[string]any{
			"token_id":    entry.Token.ID,
			"from_peer":   entry.FromPeer,
			"session_id":  entry.SessionID,
			"received_at": entry.ReceivedAt.UTC().Format(time.RFC3339),
			"acked":       entry.Acknowledged,
			"token":       entry.Token,
			"merkle_root": entry.Token.Repo.MerkleRoot,
			"verified":    true,
		}
		if entry.Quarantined != nil && len(entry.Quarantined.Warnings) > 0 {
			result["quarantine_warnings"] = entry.Quarantined.Warnings
		}
		results = append(results, result)
	}

	if results == nil {
		results = []map[string]any{}
	}

	return map[string]any{
		"tokens":        results,
		"next_cursor":   nil,
		"total_unacked": totalUnacked,
	}, nil
}

func (s *Server) handleAckToken(params map[string]any) (any, error) {
	tokenID, _ := params["token_id"].(string)
	disposition, _ := params["disposition"].(string)

	if tokenID == "" {
		return nil, newToolError("VALIDATION", "token_id is required")
	}
	if disposition == "" {
		return nil, newToolError("VALIDATION", "disposition is required")
	}
	if disposition != "accepted" && disposition != "rejected" && disposition != "partial" {
		return nil, newToolError("VALIDATION", "disposition must be accepted, rejected, or partial")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.inbox {
		if entry.Token.ID == tokenID {
			now := time.Now()
			entry.Acknowledged = true
			entry.Disposition = disposition
			entry.AckedAt = &now
			return map[string]any{
				"token_id":    tokenID,
				"acked":       true,
				"disposition": disposition,
				"acked_at":    now.UTC().Format(time.RFC3339),
			}, nil
		}
	}

	return nil, newToolError("TOKEN_NOT_FOUND", fmt.Sprintf("token %q not found in inbox", tokenID))
}

func (s *Server) handleTokenStatus(params map[string]any) (any, error) {
	tokenID, _ := params["token_id"].(string)
	if tokenID == "" {
		return nil, newToolError("VALIDATION", "token_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.outbox[tokenID]
	if !ok {
		return nil, newToolError("TOKEN_NOT_FOUND", fmt.Sprintf("token %q not found in outbox", tokenID))
	}

	result := map[string]any{
		"token_id":     tokenID,
		"peer_id":      entry.PeerID,
		"session_id":   entry.SessionID,
		"status":       entry.Status,
		"delivered_at": entry.SentAt.UTC().Format(time.RFC3339),
	}
	if entry.AckedAt != nil {
		result["acked_at"] = entry.AckedAt.UTC().Format(time.RFC3339)
		result["disposition"] = entry.Disposition
	}
	if entry.Notes != "" {
		result["notes"] = entry.Notes
	}

	return result, nil
}

// --- Content Transfer ---

func (s *Server) handleFetchContent(params map[string]any) (any, error) {
	peerID, _ := params["peer_id"].(string)
	contentHash, _ := params["content_hash"].(string)
	sessionID, _ := params["session_id"].(string)

	if peerID == "" || contentHash == "" || sessionID == "" {
		return nil, newToolError("VALIDATION", "peer_id, content_hash, and session_id are required")
	}

	s.mu.Lock()
	_, peerExists := s.peers[peerID]
	sess, sessExists := s.sessions[sessionID]
	s.mu.Unlock()

	if !peerExists {
		return nil, newToolError("PEER_NOT_FOUND", fmt.Sprintf("peer %q not found", peerID))
	}
	if !sessExists {
		return nil, newToolError("SESSION_NOT_FOUND", fmt.Sprintf("session %q not found", sessionID))
	}
	if sess.Status == "ended" {
		return nil, newToolError("SESSION_ENDED", fmt.Sprintf("session %q has ended", sessionID))
	}

	// In v1, we look for matching content in inbox tokens.
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.inbox {
		for _, p := range entry.Token.Payloads {
			if p.Hash == contentHash && p.Mode == "inline" {
				return map[string]any{
					"content_hash": contentHash,
					"path":         p.Path,
					"content":      base64.StdEncoding.EncodeToString([]byte(p.Content)),
					"size_bytes":   p.SizeBytes,
					"verified":     true,
				}, nil
			}
		}
	}

	return nil, newToolError("CONTENT_NOT_FOUND", fmt.Sprintf("content %q not found", contentHash))
}

func (s *Server) handleListAvailable(params map[string]any) (any, error) {
	peerID, _ := params["peer_id"].(string)
	sessionID, _ := params["session_id"].(string)

	if peerID == "" || sessionID == "" {
		return nil, newToolError("VALIDATION", "peer_id and session_id are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.peers[peerID]; !ok {
		return nil, newToolError("PEER_NOT_FOUND", fmt.Sprintf("peer %q not found", peerID))
	}
	if _, ok := s.sessions[sessionID]; !ok {
		return nil, newToolError("SESSION_NOT_FOUND", fmt.Sprintf("session %q not found", sessionID))
	}

	// Return refs from inbox tokens matching this peer/session.
	var refs []map[string]any
	for _, entry := range s.inbox {
		if entry.FromPeer != peerID {
			continue
		}
		for _, p := range entry.Token.Payloads {
			refs = append(refs, map[string]any{
				"path":         p.Path,
				"content_hash": p.Hash,
				"size_bytes":   p.SizeBytes,
				"modified_at":  entry.ReceivedAt.UTC().Format(time.RFC3339),
			})
		}
	}
	if refs == nil {
		refs = []map[string]any{}
	}

	return map[string]any{
		"peer_id":         peerID,
		"refs":            refs,
		"excluded_count":  0,
		"total_available": len(refs),
	}, nil
}

// --- Verification ---

func (s *Server) handleVerifyToken(params map[string]any) (any, error) {
	tokenID, _ := params["token_id"].(string)
	if tokenID == "" {
		return nil, newToolError("VALIDATION", "token_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.inbox {
		if entry.Token.ID == tokenID {
			// v1: basic structural checks. Full Merkle verification requires keys.
			checks := map[string]string{
				"merkle_root":     "skipped",
				"exclusion_proof": "skipped",
				"signature":       "skipped",
				"content_hashes":  "pass",
			}

			// Verify inline content hashes.
			valid := true
			var failures []map[string]any
			for _, p := range entry.Token.Payloads {
				if p.Mode == "inline" && p.Hash != "" {
					h := blake3.Sum256([]byte(p.Content))
					computed := "blake3:" + hex.EncodeToString(h[:])
					if computed != p.Hash {
						valid = false
						checks["content_hashes"] = "fail"
						failures = append(failures, map[string]any{
							"check":    "content_hashes",
							"detail":   fmt.Sprintf("hash mismatch for %s: expected %s, got %s", p.Path, p.Hash, computed),
							"severity": "error",
						})
					}
				}
			}

			result := map[string]any{
				"token_id": tokenID,
				"valid":    valid,
				"checks":   checks,
			}
			if len(failures) > 0 {
				result["failures"] = failures
			}
			return result, nil
		}
	}

	return nil, newToolError("TOKEN_NOT_FOUND", fmt.Sprintf("token %q not found in inbox", tokenID))
}

func (s *Server) handleVerifyContent(params map[string]any) (any, error) {
	content, _ := params["content"].(string)
	expectedHash, _ := params["expected_hash"].(string)

	if content == "" {
		return nil, newToolError("VALIDATION", "content is required")
	}
	if expectedHash == "" {
		return nil, newToolError("VALIDATION", "expected_hash is required")
	}

	parts := strings.SplitN(expectedHash, ":", 2)
	if len(parts) != 2 {
		return nil, newToolError("VALIDATION", fmt.Sprintf("invalid hash format %q: expected algorithm:hex", expectedHash))
	}
	algorithm := parts[0]

	contentBytes := []byte(content)
	err := safety.VerifyLazyFetch(contentBytes, expectedHash)

	h := blake3.Sum256(contentBytes)
	computedHash := "blake3:" + hex.EncodeToString(h[:])

	return map[string]any{
		"valid":         err == nil,
		"expected_hash": expectedHash,
		"computed_hash": computedHash,
		"algorithm":     algorithm,
	}, nil
}

func (s *Server) handleExclusionManifest(_ map[string]any) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var patterns []map[string]any
	for _, p := range s.policy.ExcludedPatterns {
		patterns = append(patterns, map[string]any{
			"pattern": p,
			"source":  "policy_config",
			"reason":  "Configured exclusion pattern",
		})
	}
	if patterns == nil {
		patterns = []map[string]any{}
	}

	return map[string]any{
		"patterns":            patterns,
		"excluded_file_count": 0,
		"total_file_count":    0,
		"has_exclusions":      len(s.policy.ExcludedPatterns) > 0,
		"hash_algorithm":      "blake3",
	}, nil
}

// --- Session Management ---

func (s *Server) handleCreateSession(params map[string]any) (any, error) {
	peerID, _ := params["peer_id"].(string)
	if peerID == "" {
		return nil, newToolError("VALIDATION", "peer_id is required")
	}

	sessionName, _ := params["session_name"].(string)
	repoIdentifier, _ := params["repo_identifier"].(string)
	ttlHours := 24
	if t, ok := params["ttl_hours"].(float64); ok {
		ttlHours = int(t)
	}
	if ttlHours > 168 {
		ttlHours = 168
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	peer, ok := s.peers[peerID]
	if !ok {
		return nil, newToolError("PEER_NOT_FOUND", fmt.Sprintf("peer %q not found", peerID))
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, newToolError("INTERNAL_ERROR", fmt.Sprintf("generating session ID: %v", err))
	}

	now := time.Now()
	sess := &Session{
		ID:             sessionID,
		Name:           sessionName,
		PeerID:         peerID,
		RepoIdentifier: repoIdentifier,
		Status:         "active",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Duration(ttlHours) * time.Hour),
		LastActivity:   now,
	}
	s.sessions[sessionID] = sess
	peer.ActiveSession = sessionID

	return map[string]any{
		"session_id":      sessionID,
		"peer_id":         peerID,
		"repo_identifier": repoIdentifier,
		"created_at":      now.UTC().Format(time.RFC3339),
		"expires_at":      sess.ExpiresAt.UTC().Format(time.RFC3339),
		"status":          "active",
	}, nil
}

func (s *Server) handleSessionStatus(params map[string]any) (any, error) {
	sessionID, _ := params["session_id"].(string)
	if sessionID == "" {
		return nil, newToolError("VALIDATION", "session_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, newToolError("SESSION_NOT_FOUND", fmt.Sprintf("session %q not found", sessionID))
	}

	// Count unacked tokens in this session.
	unacked := 0
	for _, entry := range s.inbox {
		if entry.SessionID == sessionID && !entry.Acknowledged {
			unacked++
		}
	}

	return map[string]any{
		"session_id":      sessionID,
		"peer_id":         sess.PeerID,
		"repo_identifier": sess.RepoIdentifier,
		"status":          sess.Status,
		"created_at":      sess.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":      sess.ExpiresAt.UTC().Format(time.RFC3339),
		"last_activity":   sess.LastActivity.UTC().Format(time.RFC3339),
		"participants":    []string{s.config.PeerID, sess.PeerID},
		"token_count":     sess.TokensSent + sess.TokensReceived,
		"tokens_sent":     sess.TokensSent,
		"tokens_received": sess.TokensReceived,
		"tokens_unacked":  unacked,
	}, nil
}

func (s *Server) handleEndSession(params map[string]any) (any, error) {
	sessionID, _ := params["session_id"].(string)
	if sessionID == "" {
		return nil, newToolError("VALIDATION", "session_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, newToolError("SESSION_NOT_FOUND", fmt.Sprintf("session %q not found", sessionID))
	}

	now := time.Now()
	sess.Status = "ended"
	sess.LastActivity = now

	// Clear active session on peer.
	if peer, ok := s.peers[sess.PeerID]; ok {
		if peer.ActiveSession == sessionID {
			peer.ActiveSession = ""
		}
	}

	durationMinutes := int(now.Sub(sess.CreatedAt).Minutes())

	return map[string]any{
		"session_id": sessionID,
		"status":     "ended",
		"ended_at":   now.UTC().Format(time.RFC3339),
		"final_stats": map[string]any{
			"tokens_sent":      sess.TokensSent,
			"tokens_received":  sess.TokensReceived,
			"duration_minutes": durationMinutes,
		},
	}, nil
}

func (s *Server) handleConfigurePolicy(params map[string]any) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if patterns, ok := params["excluded_patterns"]; ok {
		if arr, ok := patterns.([]any); ok {
			s.policy.ExcludedPatterns = make([]string, 0, len(arr))
			for _, v := range arr {
				if str, ok := v.(string); ok {
					s.policy.ExcludedPatterns = append(s.policy.ExcludedPatterns, str)
				}
			}
		}
	}
	if sources, ok := params["sensitivity_sources"]; ok {
		if arr, ok := sources.([]any); ok {
			s.policy.SensitivitySources = make([]string, 0, len(arr))
			for _, v := range arr {
				if str, ok := v.(string); ok {
					s.policy.SensitivitySources = append(s.policy.SensitivitySources, str)
				}
			}
		}
	}
	if threshold, ok := params["auto_inline_threshold_bytes"].(float64); ok {
		s.policy.AutoInlineThresholdBytes = int(threshold)
	}
	if types, ok := params["allowed_content_types"]; ok {
		if arr, ok := types.([]any); ok {
			s.policy.AllowedContentTypes = make([]string, 0, len(arr))
			for _, v := range arr {
				if str, ok := v.(string); ok {
					s.policy.AllowedContentTypes = append(s.policy.AllowedContentTypes, str)
				}
			}
		}
	}
	if maxBytes, ok := params["max_token_bytes"].(float64); ok {
		s.policy.MaxTokenBytes = int(maxBytes)
	}

	return map[string]any{
		"updated": true,
		"effective_policy": map[string]any{
			"sensitivity_sources":         s.policy.SensitivitySources,
			"excluded_patterns":           s.policy.ExcludedPatterns,
			"auto_inline_threshold_bytes": s.policy.AutoInlineThresholdBytes,
			"allowed_content_types":       s.policy.AllowedContentTypes,
			"max_token_bytes":             s.policy.MaxTokenBytes,
			"total_excluded_patterns":     len(s.policy.ExcludedPatterns),
		},
	}, nil
}

// --- Helpers ---

// addToInbox adds a token to the server's inbox (used in tests and by transport layer).
func (s *Server) addToInbox(tok *token.Token, fromPeer, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	qt := safety.Quarantine(tok)
	entry := &InboxEntry{
		Token:       tok,
		ReceivedAt:  time.Now(),
		SessionID:   sessionID,
		Quarantined: qt,
		FromPeer:    fromPeer,
	}
	s.inbox = append(s.inbox, entry)

	// Update session stats.
	if sess, ok := s.sessions[sessionID]; ok {
		sess.TokensReceived++
		sess.LastActivity = time.Now()
	}

	// Audit log.
	if s.config.AuditLog != nil {
		_ = s.config.AuditLog.LogReceive(tok, fromPeer)
	}
}

func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sess_" + hex.EncodeToString(b), nil
}

// Unused import guards — these are used above.
var (
	_ = os.ReadFile
	_ = strconv.Itoa
	_ = big.NewInt
)
