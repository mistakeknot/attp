package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// jsonRPCRequest is a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

// jsonRPCError is a JSON-RPC 2.0 error.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// toolDefinition is an MCP tool definition for tools/list.
type toolDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

// Run starts the JSON-RPC 2.0 stdio server, reading from stdin and writing to stdout.
func (s *Server) Run(ctx context.Context) error {
	return s.RunIO(ctx, os.Stdin, os.Stdout)
}

// RunIO is like Run but reads from r and writes to w (for testing).
func (s *Server) RunIO(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	// Allow large messages.
	scanner.Buffer(make([]byte, 0, 4*1024*1024), 4*1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error: &jsonRPCError{
					Code:    -32700,
					Message: "Parse error",
				},
			}
			writeResponse(w, resp)
			continue
		}

		resp := s.dispatch(req)
		writeResponse(w, resp)
	}

	return scanner.Err()
}

func (s *Server) dispatch(req jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "attp",
					"version": s.config.ProtocolVersion,
				},
			},
		}

	case "notifications/initialized":
		// Client acknowledgment — no response needed for notifications.
		// But since we got it as a request with an ID, respond with empty result.
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}

	case "tools/list":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.toolDefinitions(),
			},
		}

	case "tools/call":
		return s.handleToolCall(req)

	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    -32601,
				Message: fmt.Sprintf("method not found: %s", req.Method),
			},
		}
	}
}

func (s *Server) handleToolCall(req jsonRPCRequest) jsonRPCResponse {
	var callParams struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &callParams); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    -32602,
				Message: "Invalid params",
			},
		}
	}

	handler, ok := s.handlerMap()[callParams.Name]
	if !ok {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonRPCError{
				Code:    -32602,
				Message: fmt.Sprintf("unknown tool: %s", callParams.Name),
			},
		}
	}

	args := callParams.Arguments
	if args == nil {
		args = map[string]any{}
	}

	result, err := handler(args)
	if err != nil {
		// Return tool errors as MCP content with isError flag.
		errMsg := err.Error()
		if te, ok := err.(*toolError); ok {
			errMsg = te.Message
		}
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": errMsg},
				},
				"isError": true,
			},
		}
	}

	// Marshal result to JSON text for MCP content.
	resultJSON, _ := json.Marshal(result)
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": string(resultJSON)},
			},
		},
	}
}

func (s *Server) handlerMap() map[string]func(map[string]any) (any, error) {
	return map[string]func(map[string]any) (any, error){
		"list_peers":         s.handleListPeers,
		"peer_capabilities":  s.handlePeerCapabilities,
		"announce":           s.handleAnnounce,
		"push_token":         s.handlePushToken,
		"pull_tokens":        s.handlePullTokens,
		"ack_token":          s.handleAckToken,
		"token_status":       s.handleTokenStatus,
		"fetch_content":      s.handleFetchContent,
		"list_available":     s.handleListAvailable,
		"verify_token":       s.handleVerifyToken,
		"verify_content":     s.handleVerifyContent,
		"exclusion_manifest": s.handleExclusionManifest,
		"create_session":     s.handleCreateSession,
		"session_status":     s.handleSessionStatus,
		"end_session":        s.handleEndSession,
		"configure_policy":   s.handleConfigurePolicy,
	}
}

func (s *Server) toolDefinitions() []toolDefinition {
	return []toolDefinition{
		{Name: "list_peers", Description: "List known peers and their online status.", InputSchema: emptySchema()},
		{Name: "peer_capabilities", Description: "Query a peer's protocol version and feature flags.", InputSchema: schemaWithRequired("peer_id")},
		{Name: "announce", Description: "Register or update this server's identity in the peer mesh.", InputSchema: schemaWithRequired("peer_id", "endpoint", "protocol_version")},
		{Name: "push_token", Description: "Send a structured context token to a peer.", InputSchema: schemaWithRequired("peer_id", "session_id", "token", "merkle_root", "exclusion_proof")},
		{Name: "pull_tokens", Description: "Fetch inbound tokens, optionally filtered by peer or session.", InputSchema: emptySchema()},
		{Name: "ack_token", Description: "Acknowledge receipt and processing of a token.", InputSchema: schemaWithRequired("token_id", "disposition")},
		{Name: "token_status", Description: "Check delivery and acknowledgment status of a pushed token.", InputSchema: schemaWithRequired("token_id")},
		{Name: "fetch_content", Description: "Lazy-fetch a file or blob from a peer by content hash.", InputSchema: schemaWithRequired("peer_id", "content_hash", "session_id")},
		{Name: "list_available", Description: "List fetchable content references from a peer in a session.", InputSchema: schemaWithRequired("peer_id", "session_id")},
		{Name: "verify_token", Description: "Verify a token's integrity.", InputSchema: schemaWithRequired("token_id")},
		{Name: "verify_content", Description: "Verify fetched content against its expected hash.", InputSchema: schemaWithRequired("content", "expected_hash")},
		{Name: "exclusion_manifest", Description: "Return this server's current exclusion manifest.", InputSchema: emptySchema()},
		{Name: "create_session", Description: "Establish a collaboration session with a peer.", InputSchema: schemaWithRequired("peer_id")},
		{Name: "session_status", Description: "Get current session state and stats.", InputSchema: schemaWithRequired("session_id")},
		{Name: "end_session", Description: "Gracefully end a collaboration session.", InputSchema: schemaWithRequired("session_id")},
		{Name: "configure_policy", Description: "Set sensitivity policy for content sharing.", InputSchema: emptySchema()},
	}
}

func emptySchema() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

func schemaWithRequired(fields ...string) map[string]any {
	props := make(map[string]any, len(fields))
	for _, f := range fields {
		props[f] = map[string]any{"type": "string"}
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   fields,
	}
}

func writeResponse(w io.Writer, resp jsonRPCResponse) {
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	w.Write(data)
}
