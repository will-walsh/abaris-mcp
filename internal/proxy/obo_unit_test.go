package proxy_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/proxy"
)

// ---------------------------------------------------------------------------
// OBOPipeline unit tests
// ---------------------------------------------------------------------------

func TestOBOPipeline_NoUAT_Returns32001(t *testing.T) {
	store := newInMemoryTokenStore()
	// Do NOT save any UAT for the user+provider.

	rt := &recordingRoundTripper{statusCode: http.StatusOK}
	logger := &capturingLogger{}
	identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "user1", Groups: []string{"dev"}}}
	policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
	minter := &stubMinter{token: "assertion-token"}

	pipeline, err := proxy.NewOBOPipeline(proxy.OBOPipelineConfig{
		Identity:  identity,
		Policy:    policy,
		Store:     store,
		Minter:    minter,
		Transport: rt,
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("NewOBOPipeline: %v", err)
	}

	params, _ := json.Marshal(map[string]any{"name": "github/create-pr", "arguments": map[string]any{}})
	call := domain.ToolCall{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
	route := domain.RouteEntry{Prefix: "github", BackendURI: "http://backend:8080", OBOProvider: "github"}

	respBytes, err := pipeline.Execute(context.Background(), call, route)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Should return a JSON-RPC error with code -32001.
	code := errorCodeFromResponse(respBytes)
	if code != domain.CodeUnauthenticated {
		t.Errorf("expected -32001, got %d", code)
	}

	// Backend should NOT have been called.
	if rt.callCount != 0 {
		t.Errorf("expected no backend calls, got %d", rt.callCount)
	}
}

func TestOBOPipeline_PolicyDenied_Returns32004(t *testing.T) {
	store := newInMemoryTokenStore()
	_ = store.Save(context.Background(), "user1", "github", domain.TokenPair{AccessToken: "uat", RefreshToken: "r"})

	rt := &recordingRoundTripper{statusCode: http.StatusOK}
	logger := &capturingLogger{}
	identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "user1", Groups: []string{"read-only"}}}
	policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: false, DenialReason: "denied"}}
	minter := &stubMinter{token: "assertion-token"}

	pipeline, err := proxy.NewOBOPipeline(proxy.OBOPipelineConfig{
		Identity:  identity,
		Policy:    policy,
		Store:     store,
		Minter:    minter,
		Transport: rt,
		Logger:    logger,
	})
	if err != nil {
		t.Fatalf("NewOBOPipeline: %v", err)
	}

	params, _ := json.Marshal(map[string]any{"name": "github/delete-repo", "arguments": map[string]any{}})
	call := domain.ToolCall{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
	route := domain.RouteEntry{Prefix: "github", BackendURI: "http://backend:8080", OBOProvider: "github"}

	respBytes, err := pipeline.Execute(context.Background(), call, route)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	code := errorCodeFromResponse(respBytes)
	if code != domain.CodePolicyDenied {
		t.Errorf("expected -32004, got %d", code)
	}
	if rt.callCount != 0 {
		t.Errorf("expected no backend calls, got %d", rt.callCount)
	}
}

func TestOBOPipeline_ExpiredCognitoToken_SilentRefresh(t *testing.T) {
	store := newInMemoryTokenStore()
	// Store a Cognito refresh token.
	_ = store.Save(context.Background(), "user1", "cognito", domain.TokenPair{
		AccessToken:  "expired-access",
		RefreshToken: "valid-refresh",
	})
	// Store a UAT for github.
	_ = store.Save(context.Background(), "user1", "github", domain.TokenPair{AccessToken: "uat", RefreshToken: "r"})

	rt := &recordingRoundTripper{statusCode: http.StatusOK}
	logger := &capturingLogger{}

	callCount := 0
	// First call returns ErrUnauthorized (expired), second returns success.
	identity := &stubIdentityServiceWithRefresh{
		firstErr:       domain.ErrUnauthorized,
		secondIdentity: domain.IdentityContext{UserID: "user1", Groups: []string{"dev"}},
		callCount:      &callCount,
	}
	policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
	minter := &stubMinter{token: "assertion-token"}
	cognitoRefresher := &stubCognitoRefresher{
		newPair: domain.TokenPair{AccessToken: "new-access", RefreshToken: "new-refresh"},
	}

	pipeline, err := proxy.NewOBOPipeline(proxy.OBOPipelineConfig{
		Identity:         identity,
		Policy:           policy,
		Store:            store,
		Minter:           minter,
		CognitoRefresher: cognitoRefresher,
		Transport:        rt,
		Logger:           logger,
	})
	if err != nil {
		t.Fatalf("NewOBOPipeline: %v", err)
	}

	params, _ := json.Marshal(map[string]any{"name": "github/create-pr", "arguments": map[string]any{}})
	call := domain.ToolCall{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
	route := domain.RouteEntry{Prefix: "github", BackendURI: "http://backend:8080", OBOProvider: "github"}

	// Inject an expired token with a valid sub claim.
	expiredToken := buildJWTWithSub("user1")
	ctx := injectBearerToken(context.Background(), expiredToken)

	_, err = pipeline.Execute(ctx, call, route)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	// Backend should have been called once (after successful refresh).
	if rt.callCount != 1 {
		t.Errorf("expected 1 backend call after refresh, got %d", rt.callCount)
	}
}

// stubIdentityServiceWithRefresh returns an error on the first call, then succeeds.
type stubIdentityServiceWithRefresh struct {
	firstErr       error
	secondIdentity domain.IdentityContext
	callCount      *int
}

func (s *stubIdentityServiceWithRefresh) Resolve(_ context.Context) (domain.IdentityContext, error) {
	*s.callCount++
	if *s.callCount == 1 {
		return domain.IdentityContext{}, s.firstErr
	}
	return s.secondIdentity, nil
}

// stubCognitoRefresher returns a configurable new TokenPair.
// Implements proxy.CognitoRefresher: Refresh(ctx, refreshToken) (TokenPair, error).
type stubCognitoRefresher struct {
	newPair domain.TokenPair
	err     error
}

func (r *stubCognitoRefresher) Refresh(_ context.Context, _ string) (domain.TokenPair, error) {
	return r.newPair, r.err
}

// buildJWTWithSub builds a minimal unsigned JWT with the given sub claim.
// Used to test sub extraction from expired tokens.
func buildJWTWithSub(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `","exp":1}`))
	return header + "." + payload + ".fakesig"
}

// ---------------------------------------------------------------------------
// ConnectHandler unit tests
// ---------------------------------------------------------------------------

func TestConnectHandler_UnknownProvider_Returns404(t *testing.T) {
	handler := buildConnectHandler(t, []byte("test-key-32-bytes-long-here!!!!"), []domain.SecondaryProviderConfig{
		{Name: "github", Type: "oauth2", AuthURL: "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
			ClientID: "client", ClientSecretARN: "arn:test", Scopes: []string{"repo"}},
	})

	req := httptest.NewRequest(http.MethodGet, "/connect/unknown-provider", nil)
	req.SetPathValue("provider", "unknown-provider")
	w := httptest.NewRecorder()
	handler.ServeConnect(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestConnectHandler_UnknownProvider_Callback_Returns404(t *testing.T) {
	handler := buildConnectHandler(t, []byte("test-key-32-bytes-long-here!!!!"), []domain.SecondaryProviderConfig{
		{Name: "github", Type: "oauth2", AuthURL: "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
			ClientID: "client", ClientSecretARN: "arn:test", Scopes: []string{"repo"}},
	})

	req := httptest.NewRequest(http.MethodGet, "/connect/unknown-provider/callback?state=abc&code=xyz", nil)
	req.SetPathValue("provider", "unknown-provider")
	w := httptest.NewRecorder()
	handler.ServeCallback(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestConnectHandler_MissingCognitoToken_Returns401(t *testing.T) {
	// stubIdentityService returns ErrUnauthenticated when no token is present.
	store := newInMemoryTokenStore()
	identity := &stubIdentityService{err: domain.ErrUnauthenticated}
	handler, err := proxy.NewConnectHandler(proxy.ConnectHandlerConfig{
		Identity:    identity,
		Store:       store,
		Providers:   []domain.SecondaryProviderConfig{{Name: "github", Type: "oauth2", AuthURL: "https://auth.example.com", TokenURL: "https://token.example.com", ClientID: "c", ClientSecretARN: "arn:test", Scopes: []string{"read"}}},
		StateKey:    []byte("test-key-32-bytes-long-here!!!!"),
		StateTTL:    10 * time.Minute,
		RedirectURI: "https://abaris.example.com",
		Logger:      &capturingLogger{},
	})
	if err != nil {
		t.Fatalf("NewConnectHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/connect/github", nil)
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()
	handler.ServeConnect(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
