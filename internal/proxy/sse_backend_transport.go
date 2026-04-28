package proxy

// SSEBackendTransport implements domain.BackendTransport for backends that
// speak the MCP Streamable HTTP transport (spec version 2025-03-26).
//
// MCP Streamable HTTP protocol:
//
//  1. POST initialize  — negotiate protocol version; server returns an
//     Mcp-Session-Id header that must be echoed on all subsequent requests.
//  2. POST tools/list  — discover tools (with Mcp-Session-Id header).
//  3. POST tools/call  — invoke a tool (with Mcp-Session-Id header).
//
// Each Forward call opens a fresh session (initialize → request → done).
// Sessions are not reused across calls because Abaris is stateless and
// backends may expire sessions at any time.
//
// Response handling:
//   - Content-Type: application/json  → read body directly as JSON-RPC response
//   - Content-Type: text/event-stream → read SSE stream, return first "message" event data
//
// Size limits:
//   - Response bodies are capped at maxSSEResponseSize (32 MiB) to prevent
//     memory exhaustion from a misbehaving backend.
//   - Error bodies (non-200) are capped at 4 KiB for log safety.
//
// Thread safety: SSEBackendTransport is safe for concurrent use.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// maxSSEResponseSize caps backend response bodies at 32 MiB.
// Protects against memory exhaustion from a malicious or misbehaving backend.
const maxSSEResponseSize = 32 << 20 // 32 MiB

// mcpProtocolVersion is the MCP protocol version Abaris advertises during initialize.
const mcpProtocolVersion = "2024-11-05"

// SSEBackendTransport forwards MCP tool calls using the Streamable HTTP transport.
type SSEBackendTransport struct {
	client *http.Client
	logger domain.Logger
}

// NewSSEBackendTransport constructs an SSEBackendTransport.
// If client is nil, a default client with a 30s timeout is used.
func NewSSEBackendTransport(client *http.Client, logger domain.Logger) *SSEBackendTransport {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &SSEBackendTransport{client: client, logger: logger}
}

// Forward implements domain.BackendTransport using MCP Streamable HTTP.
//
// It performs the initialize handshake to obtain a session ID, then sends
// the actual JSON-RPC call in a second request using that session ID.
func (t *SSEBackendTransport) Forward(ctx context.Context, backendURL string, call domain.ToolCall, identityToken string) ([]byte, error) {
	cred, _ := ServiceCredentialFromContext(ctx)

	// Step 1: initialize — required by MCP Streamable HTTP before any other method.
	sessionID, err := t.initialize(ctx, backendURL, cred, identityToken)
	if err != nil {
		return nil, err
	}

	// Step 2: send the actual call with the session ID.
	return t.send(ctx, backendURL, call, cred, identityToken, sessionID)
}

// initialize sends an MCP initialize request and returns the Mcp-Session-Id
// from the response headers. Returns "" if the server does not issue a session ID
// (some servers are sessionless).
func (t *SSEBackendTransport) initialize(ctx context.Context, backendURL, cred, identityToken string) (string, error) {
	initCall := domain.ToolCall{
		JSONRPC: "2.0",
		ID:      0,
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "` + mcpProtocolVersion + `",
			"capabilities": {},
			"clientInfo": {"name": "abaris", "version": "1.0"}
		}`),
	}

	respBytes, respHeader, _, err := t.post(ctx, backendURL, initCall, cred, identityToken, "")
	if err != nil {
		return "", fmt.Errorf("sse backend: initialize: %w", err)
	}

	// Check for a JSON-RPC error in the initialize response.
	var initResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &initResp); err == nil && initResp.Error != nil {
		return "", fmt.Errorf("%w: sse backend: initialize rejected by server: %d %s",
			domain.ErrServiceUnavailable, initResp.Error.Code, initResp.Error.Message)
	}

	t.logger.Debug("sse backend: initialize succeeded",
		"backend", backendURL,
		"session_id", respHeader.Get("Mcp-Session-Id"),
		"response_preview", previewString(string(respBytes), 256),
	)

	return respHeader.Get("Mcp-Session-Id"), nil
}

// send posts a JSON-RPC call to the backend and returns the response bytes.
// If the server returns 404 (session expired), it automatically re-initializes
// and retries once, as required by the MCP Streamable HTTP spec.
func (t *SSEBackendTransport) send(ctx context.Context, backendURL string, call domain.ToolCall, cred, identityToken, sessionID string) ([]byte, error) {
	respBytes, _, statusCode, err := t.post(ctx, backendURL, call, cred, identityToken, sessionID)
	if err != nil && statusCode == http.StatusNotFound && sessionID != "" {
		// Session expired — spec requires starting a new session (§ Session Management).
		t.logger.Warn("sse backend: session expired (404), re-initializing", "backend", backendURL)
		newSessionID, initErr := t.initialize(ctx, backendURL, cred, identityToken)
		if initErr != nil {
			return nil, initErr
		}
		respBytes, _, _, err = t.post(ctx, backendURL, call, cred, identityToken, newSessionID)
	}
	t.logger.Debug("sse backend: send response",
		"backend", backendURL,
		"method", call.Method,
		"response_preview", previewString(string(respBytes), 512),
	)
	return respBytes, err
}

// post is the shared HTTP POST implementation used by both initialize and send.
// Returns the response body bytes, response headers, and HTTP status code.
func (t *SSEBackendTransport) post(ctx context.Context, backendURL string, call domain.ToolCall, cred, identityToken, sessionID string) ([]byte, http.Header, int, error) {
	callBytes, err := json.Marshal(call)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("sse backend: marshal call: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backendURL, bytes.NewReader(callBytes))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("%w: sse backend: create request: %s", domain.ErrServiceUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	if identityToken != "" {
		req.Header.Set("X-Abaris-Identity", identityToken)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("%w: sse backend: POST %s: %s", domain.ErrServiceUnavailable, backendURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, nil, resp.StatusCode, fmt.Errorf("%w: sse backend: POST %s returned %d: %s",
			domain.ErrServiceUnavailable, backendURL, resp.StatusCode, string(body))
	}

	ct := resp.Header.Get("Content-Type")

	var body []byte
	if strings.Contains(ct, "text/event-stream") {
		body, err = t.readFirstMessage(io.LimitReader(resp.Body, maxSSEResponseSize), backendURL)
	} else {
		// application/json or unknown — read directly.
		body, err = io.ReadAll(io.LimitReader(resp.Body, maxSSEResponseSize))
	}
	if err != nil {
		return nil, nil, resp.StatusCode, err
	}

	return body, resp.Header, resp.StatusCode, nil
}

// readFirstMessage reads an SSE stream and returns the data from the first
// "message" event (or the first bare data line if no event type is set).
// The caller is responsible for wrapping r with io.LimitReader.
func (t *SSEBackendTransport) readFirstMessage(r io.Reader, backendURL string) ([]byte, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: sse backend: read stream from %s: %s", domain.ErrServiceUnavailable, backendURL, err)
	}

	var eventType string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			eventType = ""
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if eventType == "message" || eventType == "" {
				return []byte(data), nil
			}
		}
	}

	return nil, fmt.Errorf("%w: sse backend: stream from %s closed without message event", domain.ErrServiceUnavailable, backendURL)
}

// Compile-time interface check.
var _ domain.BackendTransport = (*SSEBackendTransport)(nil)

// previewString returns up to n characters of s, appending "..." if truncated.
func previewString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
