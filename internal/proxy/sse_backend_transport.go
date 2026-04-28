package proxy

// SSEBackendTransport implements domain.BackendTransport for backends that
// speak the MCP SSE protocol (e.g. https://api.githubcopilot.com/mcp/).
//
// The MCP SSE protocol is a two-phase handshake:
//
//  1. GET <backendURL> — establishes the SSE stream. The server immediately
//     emits an "endpoint" event whose data is the POST URL to use for
//     sending JSON-RPC messages.
//
//  2. POST <endpointURL> — sends the JSON-RPC 2.0 request body. The response
//     arrives as an SSE "message" event on the stream opened in step 1.
//
// This transport manages both phases within a single Forward call, opening
// and closing the SSE stream per request. This is intentionally stateless —
// no persistent connection is maintained between calls — which keeps the
// implementation simple and avoids connection-leak issues in the broker.
//
// Thread safety: SSEBackendTransport is safe for concurrent use. Each Forward
// call creates its own HTTP requests and SSE reader.

import (
	"bufio"
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

// SSEBackendTransport forwards MCP tool calls to backends using the SSE transport protocol.
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

// Forward implements domain.BackendTransport using the MCP SSE protocol.
//
// It opens an SSE stream to backendURL, waits for the "endpoint" event to
// get the POST URL, sends the JSON-RPC call, then reads the "message" event
// containing the JSON-RPC response.
func (t *SSEBackendTransport) Forward(ctx context.Context, backendURL string, call domain.ToolCall, identityToken string) ([]byte, error) {
	cred, _ := ServiceCredentialFromContext(ctx)

	// -----------------------------------------------------------------------
	// Phase 1: Open SSE stream, read the "endpoint" event.
	// -----------------------------------------------------------------------
	sseReq, err := http.NewRequestWithContext(ctx, http.MethodGet, backendURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: sse backend: create GET request: %s", domain.ErrServiceUnavailable, err)
	}
	sseReq.Header.Set("Accept", "text/event-stream")
	if cred != "" {
		sseReq.Header.Set("Authorization", "Bearer "+cred)
	}
	if identityToken != "" {
		sseReq.Header.Set("X-Abaris-Identity", identityToken)
	}

	sseResp, err := t.client.Do(sseReq)
	if err != nil {
		return nil, fmt.Errorf("%w: sse backend: GET %s: %s", domain.ErrServiceUnavailable, backendURL, err)
	}
	defer sseResp.Body.Close()

	if sseResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(sseResp.Body, 4096))
		return nil, fmt.Errorf("%w: sse backend: GET %s returned %d: %s",
			domain.ErrServiceUnavailable, backendURL, sseResp.StatusCode, string(body))
	}

	// Read SSE events until we get the "endpoint" event.
	postURL, msgCh, errCh, err := t.readSSEStream(ctx, sseResp.Body, backendURL)
	if err != nil {
		return nil, err
	}

	// -----------------------------------------------------------------------
	// Phase 2: POST the JSON-RPC call to the endpoint URL.
	// -----------------------------------------------------------------------
	callBytes, err := json.Marshal(call)
	if err != nil {
		return nil, fmt.Errorf("sse backend: marshal call: %w", err)
	}

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(callBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: sse backend: create POST request: %s", domain.ErrServiceUnavailable, err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	if cred != "" {
		postReq.Header.Set("Authorization", "Bearer "+cred)
	}
	if identityToken != "" {
		postReq.Header.Set("X-Abaris-Identity", identityToken)
	}

	postResp, err := t.client.Do(postReq)
	if err != nil {
		return nil, fmt.Errorf("%w: sse backend: POST %s: %s", domain.ErrServiceUnavailable, postURL, err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK && postResp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(postResp.Body, 4096))
		return nil, fmt.Errorf("%w: sse backend: POST %s returned %d: %s",
			domain.ErrServiceUnavailable, postURL, postResp.StatusCode, string(body))
	}

	// -----------------------------------------------------------------------
	// Phase 3: Wait for the "message" event on the SSE stream.
	// -----------------------------------------------------------------------
	select {
	case msg := <-msgCh:
		return []byte(msg), nil
	case err := <-errCh:
		return nil, fmt.Errorf("%w: sse backend: stream error: %s", domain.ErrServiceUnavailable, err)
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: sse backend: context cancelled waiting for response", domain.ErrServiceUnavailable)
	}
}

// readSSEStream reads the SSE stream from r, extracts the "endpoint" event data
// (the POST URL), and returns a channel that will receive the first "message"
// event data. The goroutine reading the stream runs until the context is done
// or the stream closes.
func (t *SSEBackendTransport) readSSEStream(ctx context.Context, r io.Reader, backendURL string) (postURL string, msgCh <-chan string, errCh <-chan error, err error) {
	msgC := make(chan string, 1)
	errC := make(chan error, 1)

	scanner := bufio.NewScanner(r)

	// Read lines synchronously until we find the "endpoint" event, then
	// hand off to a goroutine for the "message" event.
	var eventType string
	var endpointURL string

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Blank line = end of event. Reset event type.
			eventType = ""
			continue
		}

		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}

		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if eventType == "endpoint" {
				// Resolve relative URLs against the backend base URL.
				endpointURL = resolveEndpointURL(backendURL, data)
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", nil, nil, fmt.Errorf("%w: sse backend: read stream: %s", domain.ErrServiceUnavailable, err)
	}

	if endpointURL == "" {
		return "", nil, nil, fmt.Errorf("%w: sse backend: no endpoint event received from %s", domain.ErrServiceUnavailable, backendURL)
	}

	// Continue reading in background for the "message" event.
	go func() {
		var evType string
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				errC <- ctx.Err()
				return
			default:
			}

			line := scanner.Text()
			if line == "" {
				evType = ""
				continue
			}
			if strings.HasPrefix(line, "event:") {
				evType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
				continue
			}
			if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if evType == "message" || evType == "" {
					msgC <- data
					return
				}
			}
		}
		if err := scanner.Err(); err != nil {
			errC <- err
		} else {
			errC <- fmt.Errorf("sse stream closed without message event")
		}
	}()

	return endpointURL, msgC, errC, nil
}

// resolveEndpointURL resolves the endpoint path from an SSE "endpoint" event
// against the backend base URL. If the endpoint data is already an absolute
// URL it is returned as-is.
func resolveEndpointURL(backendURL, endpointData string) string {
	if strings.HasPrefix(endpointData, "http://") || strings.HasPrefix(endpointData, "https://") {
		return endpointData
	}
	// Strip trailing slash from base, ensure leading slash on path.
	base := strings.TrimRight(backendURL, "/")
	if !strings.HasPrefix(endpointData, "/") {
		endpointData = "/" + endpointData
	}
	return base + endpointData
}

// Compile-time interface check.
var _ domain.BackendTransport = (*SSEBackendTransport)(nil)
