package proxy

// SSEBackendTransport implements domain.BackendTransport for backends that
// speak the MCP Streamable HTTP transport (spec version 2025-03-26).
//
// Streamable HTTP is a single POST to the MCP endpoint with:
//
//	Accept: application/json, text/event-stream
//
// The server responds with either:
//   - Content-Type: application/json  — a direct JSON-RPC response body
//   - Content-Type: text/event-stream — an SSE stream; the JSON-RPC response
//     arrives as a "message" event
//
// This replaces the old two-phase SSE protocol (GET to open stream, POST to
// send) which was deprecated in MCP spec 2025-03-26. GitHub Copilot's MCP
// endpoint (https://api.githubcopilot.com/mcp/) uses Streamable HTTP.
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

// maxSSEResponseSize is the maximum number of bytes read from a backend SSE
// response body. Protects against memory exhaustion from a malicious or
// misbehaving backend streaming an unbounded response.
// 32 MiB is generous for any realistic MCP tool list or tool call response.
const maxSSEResponseSize = 32 << 20 // 32 MiB

// Forward implements domain.BackendTransport using MCP Streamable HTTP.
//
// It POSTs the JSON-RPC call with Accept: application/json, text/event-stream.
// If the response is JSON it is returned directly. If it is an SSE stream,
// the first "message" event data is extracted and returned.
func (t *SSEBackendTransport) Forward(ctx context.Context, backendURL string, call domain.ToolCall, identityToken string) ([]byte, error) {
	cred, _ := ServiceCredentialFromContext(ctx)

	callBytes, err := json.Marshal(call)
	if err != nil {
		return nil, fmt.Errorf("sse backend: marshal call: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backendURL, bytes.NewReader(callBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: sse backend: create request: %s", domain.ErrServiceUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	if identityToken != "" {
		req.Header.Set("X-Abaris-Identity", identityToken)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: sse backend: POST %s: %s", domain.ErrServiceUnavailable, backendURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%w: sse backend: POST %s returned %d: %s",
			domain.ErrServiceUnavailable, backendURL, resp.StatusCode, string(body))
	}

	ct := resp.Header.Get("Content-Type")

	// Plain JSON response — return directly.
	if strings.Contains(ct, "application/json") {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxSSEResponseSize))
		if err != nil {
			return nil, fmt.Errorf("%w: sse backend: read json response: %s", domain.ErrServiceUnavailable, err)
		}
		return body, nil
	}

	// SSE stream — read until we get a "message" event.
	if strings.Contains(ct, "text/event-stream") {
		return t.readFirstMessage(io.LimitReader(resp.Body, maxSSEResponseSize), backendURL)
	}

	// Unknown content type — try reading as JSON anyway.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSSEResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: sse backend: read response: %s", domain.ErrServiceUnavailable, err)
	}
	return body, nil
}

// readFirstMessage reads an SSE stream and returns the data from the first
// "message" event (or the first data line if no event type is specified).
// Reads the full response body rather than using a line scanner, so there is
// no arbitrary size limit on individual SSE data lines. The caller is
// responsible for wrapping r with io.LimitReader before calling.
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
