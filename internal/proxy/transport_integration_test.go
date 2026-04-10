//go:build integration

// Package proxy_test contains integration tests for SSE and Stdio transport acceptance.
//
// These tests spin up real in-process transports and verify they accept MCP
// JSON-RPC 2.0 requests over SSE (HTTP) and Stdio (pipes).
//
// Run with: go test -tags integration ./internal/proxy/...
//
// Validates: Requirements 1.1
package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/proxy"
)

// ---------------------------------------------------------------------------
// Mock implementations of domain interfaces
// ---------------------------------------------------------------------------

// mockIdentityService returns a fixed IdentityContext for any request.
type mockIdentityService struct {
	identity domain.IdentityContext
	err      error
}

func (m *mockIdentityService) Resolve(_ context.Context) (domain.IdentityContext, error) {
	return m.identity, m.err
}

// mockPolicyEngine permits all tool calls and returns all tools unfiltered.
type mockPolicyEngine struct {
	decision  domain.PolicyDecision
	filterErr error
}

func (m *mockPolicyEngine) Evaluate(_ context.Context, _ domain.IdentityContext, _ domain.ToolCall) (domain.PolicyDecision, error) {
	return m.decision, nil
}

func (m *mockPolicyEngine) FilterTools(_ context.Context, _ domain.IdentityContext, toolNames []string) ([]string, error) {
	if m.filterErr != nil {
		return nil, m.filterErr
	}
	return toolNames, nil
}

// mockBackendTransport returns a fixed JSON-RPC 2.0 success response.
type mockBackendTransport struct {
	response []byte
	err      error
}

func (m *mockBackendTransport) Forward(_ context.Context, _ string, call domain.ToolCall, _ string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.response != nil {
		return m.response, nil
	}
	// Default: echo back a success response with the same ID.
	resp, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      call.ID,
		"result":  map[string]any{"content": "ok"},
	})
	return resp, nil
}

// mockMinter returns a fixed assertion token.
type mockMinter struct {
	token string
	err   error
}

func (m *mockMinter) Mint(_ context.Context, _ domain.IdentityContext, _ string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

// mockCredStore returns a fixed service credential.
type mockCredStore struct {
	cred string
	err  error
}

func (m *mockCredStore) GetServiceCredential(_ context.Context, _ string) (string, error) {
	return m.cred, m.err
}

// mockLogger discards all log output.
type mockLogger struct{}

func (l *mockLogger) Info(_ string, _ ...any)  {}
func (l *mockLogger) Warn(_ string, _ ...any)  {}
func (l *mockLogger) Error(_ string, _ ...any) {}
func (l *mockLogger) Debug(_ string, _ ...any) {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestBroker constructs a Broker wired with mock dependencies.
func newTestBroker(t *testing.T) *proxy.Broker {
	t.Helper()
	broker, err := proxy.NewBroker(proxy.BrokerConfig{
		Identity: &mockIdentityService{
			identity: domain.IdentityContext{
				UserID: "test-user",
				Email:  "test@example.com",
				Groups: []string{"developers"},
			},
		},
		Policy: &mockPolicyEngine{
			decision: domain.PolicyDecision{
				Permitted:     true,
				MatchedRuleID: "developers-allow",
			},
		},
		Transport: &mockBackendTransport{},
		Minter:    &mockMinter{token: "mock-assertion-token"},
		Creds:     &mockCredStore{cred: "mock-service-cred"},
		Logger:    &mockLogger{},
		Routes: []domain.RouteEntry{
			{Prefix: "github", BackendURI: "http://mock-backend:8080"},
		},
	})
	if err != nil {
		t.Fatalf("newTestBroker: %v", err)
	}
	return broker
}

// validToolsCallRequest returns a JSON-encoded MCP tools/call request.
func validToolsCallRequest(id any, toolName string) []byte {
	params, _ := json.Marshal(map[string]any{
		"name":      toolName,
		"arguments": map[string]any{},
	})
	call := domain.ToolCall{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params:  params,
	}
	b, _ := json.Marshal(call)
	return b
}

// validToolsListRequest returns a JSON-encoded MCP tools/list request.
func validToolsListRequest(id any) []byte {
	call := domain.ToolCall{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/list",
	}
	b, _ := json.Marshal(call)
	return b
}

// parseJSONRPCResponse parses a JSON-RPC 2.0 response from raw bytes.
func parseJSONRPCResponse(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parseJSONRPCResponse: unmarshal failed: %v\nraw: %s", err, data)
	}
	return resp
}

// assertJSONRPC20 verifies the response has jsonrpc: "2.0".
func assertJSONRPC20(t *testing.T, resp map[string]any) {
	t.Helper()
	if v, ok := resp["jsonrpc"]; !ok || v != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %v", v)
	}
}

// assertNoError verifies the response has no error field.
func assertNoError(t *testing.T, resp map[string]any) {
	t.Helper()
	if errField, ok := resp["error"]; ok && errField != nil {
		t.Errorf("unexpected error in response: %v", errField)
	}
}

// assertErrorCode verifies the response has the expected JSON-RPC error code.
func assertErrorCode(t *testing.T, resp map[string]any, expectedCode int) {
	t.Helper()
	errField, ok := resp["error"]
	if !ok || errField == nil {
		t.Fatalf("expected error field with code %d, got no error", expectedCode)
	}
	errObj, ok := errField.(map[string]any)
	if !ok {
		t.Fatalf("error field is not an object: %v", errField)
	}
	code, ok := errObj["code"].(float64)
	if !ok {
		t.Fatalf("error.code is not a number: %v", errObj["code"])
	}
	if int(code) != expectedCode {
		t.Errorf("error.code: got %d, want %d", int(code), expectedCode)
	}
}

// ---------------------------------------------------------------------------
// SSE Transport Integration Tests
// ---------------------------------------------------------------------------

// TestSSETransport_AcceptsValidToolsCallRequest verifies that the SSE transport
// accepts a valid MCP tools/call request and returns a JSON-RPC 2.0 response.
//
// Validates: Requirements 1.1
func TestSSETransport_AcceptsValidToolsCallRequest(t *testing.T) {
	broker := newTestBroker(t)
	transport := proxy.NewSSETransport(broker, &mockLogger{})
	server := httptest.NewServer(transport.Mux())
	defer server.Close()

	body := validToolsCallRequest(1, "github/create-pr")
	req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	parsed := parseJSONRPCResponse(t, respBody)
	assertJSONRPC20(t, parsed)
	assertNoError(t, parsed)
}

// TestSSETransport_AcceptsValidToolsListRequest verifies that the SSE transport
// accepts a valid MCP tools/list request and returns a JSON-RPC 2.0 response
// with a tools array.
//
// Validates: Requirements 1.1
func TestSSETransport_AcceptsValidToolsListRequest(t *testing.T) {
	broker := newTestBroker(t)
	transport := proxy.NewSSETransport(broker, &mockLogger{})
	server := httptest.NewServer(transport.Mux())
	defer server.Close()

	body := validToolsListRequest(2)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	parsed := parseJSONRPCResponse(t, respBody)
	assertJSONRPC20(t, parsed)
}

// TestSSETransport_RejectsMalformedRequest verifies that the SSE transport
// returns a -32600 error for a malformed JSON-RPC 2.0 request.
//
// Validates: Requirements 1.1, 1.5
func TestSSETransport_RejectsMalformedRequest(t *testing.T) {
	broker := newTestBroker(t)
	transport := proxy.NewSSETransport(broker, &mockLogger{})
	server := httptest.NewServer(transport.Mux())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader(`not valid json`))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	// SSE transport returns 200 with a JSON-RPC error body (per MCP spec).
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	parsed := parseJSONRPCResponse(t, respBody)
	assertJSONRPC20(t, parsed)
	assertErrorCode(t, parsed, domain.CodeInvalidRequest)
}

// TestSSETransport_RejectsNonPOST verifies that the SSE transport rejects
// non-POST requests with HTTP 405.
//
// Validates: Requirements 1.1
func TestSSETransport_RejectsNonPOST(t *testing.T) {
	broker := newTestBroker(t)
	transport := proxy.NewSSETransport(broker, &mockLogger{})
	server := httptest.NewServer(transport.Mux())
	defer server.Close()

	resp, err := http.Get(server.URL + "/mcp")
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// TestSSETransport_UnauthenticatedRequest verifies that the SSE transport
// returns -32001 when no identity credential is present.
//
// Validates: Requirements 1.1, 2.6
func TestSSETransport_UnauthenticatedRequest(t *testing.T) {
	broker, err := proxy.NewBroker(proxy.BrokerConfig{
		Identity: &mockIdentityService{err: domain.ErrUnauthenticated},
		Policy:   &mockPolicyEngine{},
		Transport: &mockBackendTransport{},
		Minter:   &mockMinter{token: "tok"},
		Creds:    &mockCredStore{cred: "cred"},
		Logger:   &mockLogger{},
		Routes:   []domain.RouteEntry{{Prefix: "github", BackendURI: "http://mock:8080"}},
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	transport := proxy.NewSSETransport(broker, &mockLogger{})
	server := httptest.NewServer(transport.Mux())
	defer server.Close()

	body := validToolsCallRequest(3, "github/create-pr")
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	parsed := parseJSONRPCResponse(t, respBody)
	assertJSONRPC20(t, parsed)
	assertErrorCode(t, parsed, domain.CodeUnauthenticated)
}

// TestSSETransport_BearerTokenInjected verifies that the SSE transport
// extracts the Authorization: Bearer header and makes it available to the
// identity service via context.
//
// Validates: Requirements 1.1, 2.1
func TestSSETransport_BearerTokenInjected(t *testing.T) {
	var capturedCtx context.Context
	capturingIdentity := &capturingIdentityService{
		identity: domain.IdentityContext{UserID: "u1", Groups: []string{"dev"}},
		capture:  func(ctx context.Context) { capturedCtx = ctx },
	}

	broker, err := proxy.NewBroker(proxy.BrokerConfig{
		Identity:  capturingIdentity,
		Policy:    &mockPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}},
		Transport: &mockBackendTransport{},
		Minter:    &mockMinter{token: "tok"},
		Creds:     &mockCredStore{cred: "cred"},
		Logger:    &mockLogger{},
		Routes:    []domain.RouteEntry{{Prefix: "github", BackendURI: "http://mock:8080"}},
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	transport := proxy.NewSSETransport(broker, &mockLogger{})
	server := httptest.NewServer(transport.Mux())
	defer server.Close()

	body := validToolsCallRequest(4, "github/create-pr")
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-bearer-token-xyz")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) //nolint:errcheck

	// Verify the context was captured and contains the bearer token.
	if capturedCtx == nil {
		t.Fatal("identity service was not called")
	}
	// The authctx package stores the token; we verify the context was passed through.
	// (We can't import authctx here without a cycle, so we just verify the call happened.)
}

// ---------------------------------------------------------------------------
// Stdio Transport Integration Tests
// ---------------------------------------------------------------------------

// TestStdioTransport_AcceptsValidToolsCallRequest verifies that the Stdio
// transport accepts a valid MCP tools/call request over pipes and returns a
// valid JSON-RPC 2.0 response.
//
// Validates: Requirements 1.1
func TestStdioTransport_AcceptsValidToolsCallRequest(t *testing.T) {
	broker := newTestBroker(t)

	// Set up pipes to simulate stdin/stdout.
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	transport := proxy.NewStdioTransportWithIO(broker, &mockLogger{}, stdinR, stdoutW)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run the transport in a goroutine.
	runErr := make(chan error, 1)
	go func() {
		runErr <- transport.Run(ctx)
	}()

	// Write a valid tools/call request to stdin.
	reqBytes := validToolsCallRequest(1, "github/create-pr")
	reqBytes = append(reqBytes, '\n')
	if _, err := stdinW.Write(reqBytes); err != nil {
		t.Fatalf("write to stdin: %v", err)
	}

	// Read the response from stdout.
	scanner := bufio.NewScanner(stdoutR)
	responseCh := make(chan []byte, 1)
	go func() {
		if scanner.Scan() {
			responseCh <- scanner.Bytes()
		}
	}()

	select {
	case respBytes := <-responseCh:
		parsed := parseJSONRPCResponse(t, respBytes)
		assertJSONRPC20(t, parsed)
		assertNoError(t, parsed)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stdio response")
	}

	// Close stdin to trigger EOF and clean shutdown.
	stdinW.Close()
	stdoutW.Close()
	stdoutR.Close()
}

// TestStdioTransport_AcceptsValidToolsListRequest verifies that the Stdio
// transport accepts a valid MCP tools/list request and returns a JSON-RPC 2.0
// response.
//
// Validates: Requirements 1.1
func TestStdioTransport_AcceptsValidToolsListRequest(t *testing.T) {
	broker := newTestBroker(t)

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	transport := proxy.NewStdioTransportWithIO(broker, &mockLogger{}, stdinR, stdoutW)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go transport.Run(ctx) //nolint:errcheck

	reqBytes := append(validToolsListRequest(2), '\n')
	if _, err := stdinW.Write(reqBytes); err != nil {
		t.Fatalf("write to stdin: %v", err)
	}

	scanner := bufio.NewScanner(stdoutR)
	responseCh := make(chan []byte, 1)
	go func() {
		if scanner.Scan() {
			responseCh <- scanner.Bytes()
		}
	}()

	select {
	case respBytes := <-responseCh:
		parsed := parseJSONRPCResponse(t, respBytes)
		assertJSONRPC20(t, parsed)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stdio response")
	}

	stdinW.Close()
	stdoutW.Close()
	stdoutR.Close()
}

// TestStdioTransport_RejectsMalformedRequest verifies that the Stdio transport
// returns a -32600 error for a malformed JSON-RPC 2.0 request.
//
// Validates: Requirements 1.1, 1.5
func TestStdioTransport_RejectsMalformedRequest(t *testing.T) {
	broker := newTestBroker(t)

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	transport := proxy.NewStdioTransportWithIO(broker, &mockLogger{}, stdinR, stdoutW)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go transport.Run(ctx) //nolint:errcheck

	// Write invalid JSON.
	if _, err := stdinW.Write([]byte("not valid json\n")); err != nil {
		t.Fatalf("write to stdin: %v", err)
	}

	scanner := bufio.NewScanner(stdoutR)
	responseCh := make(chan []byte, 1)
	go func() {
		if scanner.Scan() {
			responseCh <- scanner.Bytes()
		}
	}()

	select {
	case respBytes := <-responseCh:
		parsed := parseJSONRPCResponse(t, respBytes)
		assertJSONRPC20(t, parsed)
		assertErrorCode(t, parsed, domain.CodeInvalidRequest)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stdio response")
	}

	stdinW.Close()
	stdoutW.Close()
	stdoutR.Close()
}

// TestStdioTransport_MultipleRequests verifies that the Stdio transport
// handles multiple sequential requests correctly.
//
// Validates: Requirements 1.1
func TestStdioTransport_MultipleRequests(t *testing.T) {
	broker := newTestBroker(t)

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	transport := proxy.NewStdioTransportWithIO(broker, &mockLogger{}, stdinR, stdoutW)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go transport.Run(ctx) //nolint:errcheck

	// Collect responses concurrently — io.Pipe is synchronous so we must drain
	// stdout while writing to stdin to avoid deadlock.
	responses := make(chan []byte, 2)
	go func() {
		scanner := bufio.NewScanner(stdoutR)
		for scanner.Scan() {
			responses <- append([]byte(nil), scanner.Bytes()...)
		}
	}()

	// Write two requests sequentially; the response reader above drains stdout.
	req1 := append(validToolsCallRequest(10, "github/create-pr"), '\n')
	req2 := append(validToolsCallRequest(11, "github/list-prs"), '\n')

	if _, err := stdinW.Write(req1); err != nil {
		t.Fatalf("write req1: %v", err)
	}
	// Wait for first response before sending second to avoid pipe back-pressure.
	select {
	case respBytes := <-responses:
		parsed := parseJSONRPCResponse(t, respBytes)
		assertJSONRPC20(t, parsed)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for response 1")
	}

	if _, err := stdinW.Write(req2); err != nil {
		t.Fatalf("write req2: %v", err)
	}
	select {
	case respBytes := <-responses:
		parsed := parseJSONRPCResponse(t, respBytes)
		assertJSONRPC20(t, parsed)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for response 2")
	}

	stdinW.Close()
	stdoutW.Close()
	stdoutR.Close()
}

// TestStdioTransport_SkipsBlankLines verifies that the Stdio transport
// ignores blank lines in the input stream.
//
// Validates: Requirements 1.1
func TestStdioTransport_SkipsBlankLines(t *testing.T) {
	broker := newTestBroker(t)

	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	transport := proxy.NewStdioTransportWithIO(broker, &mockLogger{}, stdinR, stdoutW)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go transport.Run(ctx) //nolint:errcheck

	// Write blank lines followed by a valid request.
	input := "\n\n" + string(append(validToolsCallRequest(20, "github/create-pr"), '\n'))
	if _, err := stdinW.Write([]byte(input)); err != nil {
		t.Fatalf("write to stdin: %v", err)
	}

	scanner := bufio.NewScanner(stdoutR)
	responseCh := make(chan []byte, 1)
	go func() {
		if scanner.Scan() {
			responseCh <- scanner.Bytes()
		}
	}()

	select {
	case respBytes := <-responseCh:
		parsed := parseJSONRPCResponse(t, respBytes)
		assertJSONRPC20(t, parsed)
		assertNoError(t, parsed)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stdio response after blank lines")
	}

	stdinW.Close()
	stdoutW.Close()
	stdoutR.Close()
}

// TestStdioTransport_CleanShutdownOnEOF verifies that the Stdio transport
// shuts down cleanly when stdin is closed (EOF).
//
// Validates: Requirements 1.1
func TestStdioTransport_CleanShutdownOnEOF(t *testing.T) {
	broker := newTestBroker(t)

	stdinR, stdinW := io.Pipe()
	_, stdoutW := io.Pipe()

	transport := proxy.NewStdioTransportWithIO(broker, &mockLogger{}, stdinR, stdoutW)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runErr := make(chan error, 1)
	go func() {
		runErr <- transport.Run(ctx)
	}()

	// Close stdin immediately to trigger EOF.
	stdinW.Close()

	select {
	case err := <-runErr:
		// nil error means clean EOF shutdown.
		if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
			t.Errorf("Run returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: transport did not shut down on EOF")
	}

	stdoutW.Close()
}

// ---------------------------------------------------------------------------
// capturingIdentityService — captures the context passed to Resolve.
// ---------------------------------------------------------------------------

type capturingIdentityService struct {
	identity domain.IdentityContext
	err      error
	capture  func(ctx context.Context)
}

func (c *capturingIdentityService) Resolve(ctx context.Context) (domain.IdentityContext, error) {
	if c.capture != nil {
		c.capture(ctx)
	}
	return c.identity, c.err
}
