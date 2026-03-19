package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/mistakeknot/attp/pkg/safety"
	"github.com/mistakeknot/attp/pkg/token"
)

func testServer(confirmer safety.Confirmer) *Server {
	var audit bytes.Buffer
	cfg := Config{
		PeerID:          "test-server",
		DisplayName:     "Test Server",
		ProtocolVersion: "1.0",
		Features:        []string{"merkle_exclusion_v1"},
		Confirmer:       confirmer,
		AuditLog:        safety.NewAuditLog(&audit),
	}
	return New(cfg)
}

func buildTestToken() *token.Token {
	tok, err := token.NewBuilder().
		SetProvenance(
			token.Origin{AgentID: "agent-1", SessionID: "sess-1"},
			map[string]token.Participant{"agent-1": {Role: "sender", VectorClockIndex: 0}},
			map[string]int{"agent-1": 1},
			1,
		).
		SetRepo("https://github.com/test/repo", "main", "abc123", nil, "blake3:deadbeef").
		SetSensitivity(false, nil, nil).
		AddInlinePayload("src/main.go", "package main", token.WithHash("")).
		Build()
	if err != nil {
		panic(err)
	}
	// Fix the hash so it matches the content.
	for i := range tok.Payloads {
		if tok.Payloads[i].Hash == "" {
			tok.Payloads[i].Hash = ""
		}
	}
	return tok
}

func registerPeer(t *testing.T, s *Server, peerID, endpoint string) {
	t.Helper()
	_, err := s.handleAnnounce(map[string]any{
		"peer_id":          peerID,
		"endpoint":         endpoint,
		"protocol_version": "1.0",
	})
	if err != nil {
		t.Fatalf("announce failed: %v", err)
	}
}

func createSession(t *testing.T, s *Server, peerID string) string {
	t.Helper()
	result, err := s.handleCreateSession(map[string]any{
		"peer_id":      peerID,
		"session_name": "test session",
	})
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}
	m := result.(map[string]any)
	return m["session_id"].(string)
}

func TestAnnounceAndListPeers(t *testing.T) {
	s := testServer(safety.AlwaysConfirm{})

	// Announce a peer.
	result, err := s.handleAnnounce(map[string]any{
		"peer_id":          "peer-1",
		"display_name":     "Peer One",
		"endpoint":         "stdio://peer-1",
		"protocol_version": "1.0",
		"features":         []any{"merkle_exclusion_v1", "lazy_fetch"},
	})
	if err != nil {
		t.Fatalf("announce error: %v", err)
	}
	m := result.(map[string]any)
	if m["announced"] != true {
		t.Errorf("expected announced=true, got %v", m["announced"])
	}

	// List peers.
	result, err = s.handleListPeers(nil)
	if err != nil {
		t.Fatalf("list_peers error: %v", err)
	}
	m = result.(map[string]any)
	peers := m["peers"].([]map[string]any)
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0]["peer_id"] != "peer-1" {
		t.Errorf("expected peer_id=peer-1, got %v", peers[0]["peer_id"])
	}
	if peers[0]["status"] != "online" {
		t.Errorf("expected status=online, got %v", peers[0]["status"])
	}
}

func TestCreateSessionAndStatus(t *testing.T) {
	s := testServer(safety.AlwaysConfirm{})
	registerPeer(t, s, "peer-1", "stdio://peer-1")

	// Create session.
	result, err := s.handleCreateSession(map[string]any{
		"peer_id":      "peer-1",
		"session_name": "code review",
	})
	if err != nil {
		t.Fatalf("create_session error: %v", err)
	}
	m := result.(map[string]any)
	sessionID := m["session_id"].(string)
	if sessionID == "" {
		t.Fatal("expected non-empty session_id")
	}
	if m["status"] != "active" {
		t.Errorf("expected status=active, got %v", m["status"])
	}

	// Check status.
	result, err = s.handleSessionStatus(map[string]any{"session_id": sessionID})
	if err != nil {
		t.Fatalf("session_status error: %v", err)
	}
	m = result.(map[string]any)
	if m["status"] != "active" {
		t.Errorf("expected active, got %v", m["status"])
	}
	if m["peer_id"] != "peer-1" {
		t.Errorf("expected peer-1, got %v", m["peer_id"])
	}
}

func TestPushTokenAlwaysConfirm(t *testing.T) {
	s := testServer(safety.AlwaysConfirm{})
	registerPeer(t, s, "peer-1", "stdio://peer-1")
	sessionID := createSession(t, s, "peer-1")

	tok := buildTestToken()
	tokJSON, _ := json.Marshal(tok)
	var tokMap map[string]any
	json.Unmarshal(tokJSON, &tokMap)

	result, err := s.handlePushToken(map[string]any{
		"peer_id":         "peer-1",
		"session_id":      sessionID,
		"token":           tokMap,
		"merkle_root":     tok.Repo.MerkleRoot,
		"exclusion_proof": map[string]any{},
	})
	if err != nil {
		t.Fatalf("push_token error: %v", err)
	}
	m := result.(map[string]any)
	if m["status"] != "delivered" {
		t.Errorf("expected delivered, got %v", m["status"])
	}
	tokenID := m["token_id"].(string)

	// Verify in outbox.
	if _, ok := s.outbox[tokenID]; !ok {
		t.Error("token not found in outbox")
	}
}

func TestPushTokenAlwaysDeny(t *testing.T) {
	s := testServer(safety.AlwaysDeny{})
	registerPeer(t, s, "peer-1", "stdio://peer-1")
	sessionID := createSession(t, s, "peer-1")

	tok := buildTestToken()
	tokJSON, _ := json.Marshal(tok)
	var tokMap map[string]any
	json.Unmarshal(tokJSON, &tokMap)

	_, err := s.handlePushToken(map[string]any{
		"peer_id":         "peer-1",
		"session_id":      sessionID,
		"token":           tokMap,
		"merkle_root":     tok.Repo.MerkleRoot,
		"exclusion_proof": map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error from denied push")
	}
	te, ok := err.(*toolError)
	if !ok {
		t.Fatalf("expected toolError, got %T", err)
	}
	if te.Type != "POLICY_VIOLATION" {
		t.Errorf("expected POLICY_VIOLATION, got %s", te.Type)
	}
}

func TestPullTokensAndQuarantine(t *testing.T) {
	s := testServer(safety.AlwaysConfirm{})
	registerPeer(t, s, "peer-1", "stdio://peer-1")
	sessionID := createSession(t, s, "peer-1")

	tok := buildTestToken()

	// Directly add to inbox (simulating receive).
	s.addToInbox(tok, "peer-1", sessionID)

	result, err := s.handlePullTokens(map[string]any{})
	if err != nil {
		t.Fatalf("pull_tokens error: %v", err)
	}
	m := result.(map[string]any)
	tokens := m["tokens"].([]map[string]any)
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0]["token_id"] != tok.ID {
		t.Errorf("expected token ID %s, got %v", tok.ID, tokens[0]["token_id"])
	}
	if tokens[0]["acked"] != false {
		t.Errorf("expected acked=false")
	}
	unacked := m["total_unacked"].(int)
	if unacked != 1 {
		t.Errorf("expected total_unacked=1, got %d", unacked)
	}
}

func TestAckToken(t *testing.T) {
	s := testServer(safety.AlwaysConfirm{})
	registerPeer(t, s, "peer-1", "stdio://peer-1")
	sessionID := createSession(t, s, "peer-1")

	tok := buildTestToken()
	s.addToInbox(tok, "peer-1", sessionID)

	// Ack the token.
	result, err := s.handleAckToken(map[string]any{
		"token_id":    tok.ID,
		"disposition": "accepted",
	})
	if err != nil {
		t.Fatalf("ack_token error: %v", err)
	}
	m := result.(map[string]any)
	if m["acked"] != true {
		t.Errorf("expected acked=true")
	}
	if m["disposition"] != "accepted" {
		t.Errorf("expected accepted, got %v", m["disposition"])
	}

	// Pull again with unacked filter — should be empty.
	result, err = s.handlePullTokens(map[string]any{"status_filter": "unacked"})
	if err != nil {
		t.Fatalf("pull_tokens error: %v", err)
	}
	m = result.(map[string]any)
	tokens := m["tokens"].([]map[string]any)
	if len(tokens) != 0 {
		t.Errorf("expected 0 unacked tokens, got %d", len(tokens))
	}
}

func TestEndSession(t *testing.T) {
	s := testServer(safety.AlwaysConfirm{})
	registerPeer(t, s, "peer-1", "stdio://peer-1")
	sessionID := createSession(t, s, "peer-1")

	result, err := s.handleEndSession(map[string]any{"session_id": sessionID})
	if err != nil {
		t.Fatalf("end_session error: %v", err)
	}
	m := result.(map[string]any)
	if m["status"] != "ended" {
		t.Errorf("expected ended, got %v", m["status"])
	}

	// Verify session is ended.
	result, err = s.handleSessionStatus(map[string]any{"session_id": sessionID})
	if err != nil {
		t.Fatalf("session_status error: %v", err)
	}
	m = result.(map[string]any)
	if m["status"] != "ended" {
		t.Errorf("expected ended status, got %v", m["status"])
	}
}

func TestPushTokenToEndedSession(t *testing.T) {
	s := testServer(safety.AlwaysConfirm{})
	registerPeer(t, s, "peer-1", "stdio://peer-1")
	sessionID := createSession(t, s, "peer-1")

	// End the session.
	_, err := s.handleEndSession(map[string]any{"session_id": sessionID})
	if err != nil {
		t.Fatalf("end_session error: %v", err)
	}

	// Try to push to ended session.
	tok := buildTestToken()
	tokJSON, _ := json.Marshal(tok)
	var tokMap map[string]any
	json.Unmarshal(tokJSON, &tokMap)

	_, err = s.handlePushToken(map[string]any{
		"peer_id":         "peer-1",
		"session_id":      sessionID,
		"token":           tokMap,
		"merkle_root":     tok.Repo.MerkleRoot,
		"exclusion_proof": map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error pushing to ended session")
	}
	te := err.(*toolError)
	if te.Type != "SESSION_ENDED" {
		t.Errorf("expected SESSION_ENDED, got %s", te.Type)
	}
}

func TestAckTokenNotFound(t *testing.T) {
	s := testServer(safety.AlwaysConfirm{})

	_, err := s.handleAckToken(map[string]any{
		"token_id":    "nonexistent",
		"disposition": "accepted",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
	te := err.(*toolError)
	if te.Type != "TOKEN_NOT_FOUND" {
		t.Errorf("expected TOKEN_NOT_FOUND, got %s", te.Type)
	}
}
