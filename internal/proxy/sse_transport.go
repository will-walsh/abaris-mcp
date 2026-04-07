package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// SSETransport accepts inbound MCP requests over HTTP and dispatches them to
// the Broker. It binds to the PORT environment variable (Requirement 9.5).
//
// MCP over SSE uses a POST /mcp endpoint: the client sends a JSON-RPC 2.0
// request body and receives the JSON-RPC 2.0 response synchronously.
type SSETransport struct {
	broker *Broker
	logger domain.Logger
	mux    *http.ServeMux
}

// NewSSETransport constructs an SSETransport wrapping the given Broker.
func NewSSETransport(broker *Broker, logger domain.Logger) *SSETransport {
	t := &SSETransport{
		broker: broker,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	t.mux.HandleFunc("/mcp", t.handleMCP)
	return t
}

// Mux returns the underlying ServeMux so the composition root can register
// additional handlers (e.g. /health, /.well-known/jwks.json, /connect/{provider}).
func (t *SSETransport) Mux() *http.ServeMux {
	return t.mux
}

// ListenAddr returns the address the SSE transport should bind to.
// Uses the PORT environment variable; defaults to ":8080" if unset.
func ListenAddr() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if !strings.Contains(port, ":") {
		return ":" + port
	}
	return port
}

// handleMCP is the HTTP handler for POST /mcp.
func (t *SSETransport) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB limit
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(ErrorResponse(nil, domain.CodeInvalidRequest, "could not read request body"))
		return
	}

	ctx := injectCredentialsFromHTTP(r.Context(), r)
	resp := t.broker.Handle(ctx, body, "sse")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// injectCredentialsFromHTTP extracts the Bearer token or SAML assertion from
// the HTTP request and stores them in the context for the identity adapters.
func injectCredentialsFromHTTP(ctx context.Context, r *http.Request) context.Context {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		ctx = authctx.WithBearerToken(ctx, strings.TrimPrefix(auth, "Bearer "))
	}
	if assertion := r.Header.Get("X-SAML-Assertion"); assertion != "" {
		ctx = authctx.WithSAMLAssertion(ctx, assertion)
	}
	return ctx
}

// ---------------------------------------------------------------------------
// HTTPBackendTransport
// ---------------------------------------------------------------------------

// HTTPBackendTransport implements domain.BackendTransport by forwarding
// ToolCall requests to backend MCP servers over HTTP.
//
// It attaches:
//   - Authorization: Bearer <service_credential> (from context via WithServiceCredential)
//   - X-Abaris-Identity: <identityToken> (the signed assertion JWT)
//
// The caller's raw credential is never forwarded (Requirement 4.5).
type HTTPBackendTransport struct {
	client *http.Client
	logger domain.Logger
}

// NewHTTPBackendTransport constructs an HTTPBackendTransport.
// If client is nil, http.DefaultClient is used.
func NewHTTPBackendTransport(client *http.Client, logger domain.Logger) *HTTPBackendTransport {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPBackendTransport{client: client, logger: logger}
}

// Forward implements domain.BackendTransport.
// identityToken is attached as X-Abaris-Identity.
// The service credential is retrieved from context (set by Broker via WithServiceCredential).
func (t *HTTPBackendTransport) Forward(ctx context.Context, backendURL string, call domain.ToolCall, identityToken string) ([]byte, error) {
	body, err := json.Marshal(call)
	if err != nil {
		return nil, fmt.Errorf("marshal tool call: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backendURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: create request: %s", domain.ErrServiceUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Attach service credential from context — never the caller's raw token.
	if cred, ok := ServiceCredentialFromContext(ctx); ok && cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}

	// Attach Identity Assertion Token.
	if identityToken != "" {
		req.Header.Set("X-Abaris-Identity", identityToken)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrServiceUnavailable, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %s", domain.ErrServiceUnavailable, err)
	}

	return respBody, nil
}

// Compile-time interface check.
var _ domain.BackendTransport = (*HTTPBackendTransport)(nil)
