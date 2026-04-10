//go:build integration

// Package proxy_test contains integration tests for OBO proxy components.
//
// These tests use httptest servers to simulate OAuth2 providers and backends.
// No external dependencies required (no LocalStack needed for these tests).
// Run with: go test -tags integration ./internal/proxy/...
//
// Test cases:
//  1. ConnectHandler end-to-end with mock OAuth2 provider
//  2. RefreshTransport 401-retry against mock backend
//
// Validates: Requirements 13.1, 12.5
package proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/proxy"
)

// ---------------------------------------------------------------------------
// Test 1: ConnectHandler end-to-end with mock OAuth2 provider
// Validates: Requirements 13.1
// ---------------------------------------------------------------------------

func TestConnectHandler_Integration_EndToEnd(t *testing.T) {
	// Start a mock OAuth2 token endpoint.
	tokenEndpointCalled := false
	mockOAuth2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenEndpointCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"access_token":  "integration-access-token",
				"refresh_token": "integration-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockOAuth2Server.Close()

	store := newInMemoryTokenStore()
	identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "user-integration-001"}}
	stateKey := []byte("integration-test-hmac-key-32byte")

	providers := []domain.SecondaryProviderConfig{
		{
			Name:            "mock-provider",
			Type:            "oauth2",
			AuthURL:         mockOAuth2Server.URL + "/auth",
			TokenURL:        mockOAuth2Server.URL + "/token",
			ClientID:        "integration-client-id",
			ClientSecret:    "integration-client-secret",
			ClientSecretARN: "arn:test",
			Scopes:          []string{"read", "write"},
		},
	}

	handler, err := proxy.NewConnectHandler(proxy.ConnectHandlerConfig{
		Identity:    identity,
		Store:       store,
		Providers:   providers,
		StateKey:    stateKey,
		StateTTL:    10 * time.Minute,
		RedirectURI: "https://abaris.example.com",
		Logger:      &capturingLogger{},
	})
	if err != nil {
		t.Fatalf("NewConnectHandler: %v", err)
	}

	// Step 1: GET /connect/mock-provider — should redirect to auth URL.
	connectReq := httptest.NewRequest(http.MethodGet, "/connect/mock-provider", nil)
	connectReq.SetPathValue("provider", "mock-provider")
	connectW := httptest.NewRecorder()
	handler.ServeConnect(connectW, connectReq)

	if connectW.Code != http.StatusFound {
		t.Fatalf("ServeConnect: expected 302, got %d", connectW.Code)
	}
	location := connectW.Header().Get("Location")
	if !strings.Contains(location, mockOAuth2Server.URL+"/auth") {
		t.Errorf("redirect location should contain auth URL, got %q", location)
	}

	// Extract state from the redirect URL.
	parsedLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	state := parsedLocation.Query().Get("state")
	if state == "" {
		t.Fatal("state parameter missing from redirect URL")
	}

	// Step 2: GET /connect/mock-provider/callback — exchange code for token.
	callbackURL := fmt.Sprintf("/connect/mock-provider/callback?state=%s&code=integration-auth-code", url.QueryEscape(state))
	callbackReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	callbackReq.SetPathValue("provider", "mock-provider")
	callbackW := httptest.NewRecorder()
	handler.ServeCallback(callbackW, callbackReq)

	if callbackW.Code != http.StatusOK {
		t.Fatalf("ServeCallback: expected 200, got %d (body: %s)", callbackW.Code, callbackW.Body.String())
	}

	// Verify token endpoint was called.
	if !tokenEndpointCalled {
		t.Error("mock OAuth2 token endpoint was not called")
	}

	// Verify token pair was saved.
	pair, err := store.Get(context.Background(), "user-integration-001", "mock-provider")
	if err != nil {
		t.Fatalf("store.Get after callback: %v", err)
	}
	if pair.AccessToken != "integration-access-token" {
		t.Errorf("stored access token: got %q, want integration-access-token", pair.AccessToken)
	}
}

// ---------------------------------------------------------------------------
// Test 2: RefreshTransport 401-retry against mock backend
// Validates: Requirements 12.5
// ---------------------------------------------------------------------------

func TestRefreshTransport_Integration_401Retry(t *testing.T) {
	callCount := 0
	var receivedTokens []string

	// Mock backend: first call returns 401, second returns 200.
	mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		receivedTokens = append(receivedTokens, r.Header.Get("Authorization"))
		if callCount == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}}) //nolint:errcheck
	}))
	defer mockBackend.Close()

	store := newInMemoryTokenStore()
	_ = store.Save(context.Background(), "user1", "mock-provider", domain.TokenPair{
		AccessToken:  "old-access-token",
		RefreshToken: "valid-refresh-token",
	})

	refresher := &stubTokenRefresher{
		newPair: domain.TokenPair{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
		},
	}
	logger := &capturingLogger{}
	transport := proxy.NewRefreshTransport(http.DefaultTransport, refresher, logger)

	req, err := http.NewRequest(http.MethodPost, mockBackend.URL, strings.NewReader(`{"jsonrpc":"2.0","method":"tools/call","id":1}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer old-access-token")
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(proxy.WithOBOContextForTest(context.Background(), store, "user1", "mock-provider"))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	// Should have made 2 calls total.
	if callCount != 2 {
		t.Errorf("expected 2 backend calls, got %d", callCount)
	}

	// First call used old token, second used new token.
	if len(receivedTokens) < 2 {
		t.Fatalf("expected 2 received tokens, got %d", len(receivedTokens))
	}
	if receivedTokens[0] != "Bearer old-access-token" {
		t.Errorf("first call token: got %q, want Bearer old-access-token", receivedTokens[0])
	}
	if receivedTokens[1] != "Bearer new-access-token" {
		t.Errorf("second call token: got %q, want Bearer new-access-token", receivedTokens[1])
	}

	// Refresher called exactly once.
	if refresher.calls != 1 {
		t.Errorf("refresher calls: got %d, want 1", refresher.calls)
	}

	// New token pair saved to store.
	savedPair, err := store.Get(context.Background(), "user1", "mock-provider")
	if err != nil {
		t.Fatalf("store.Get after refresh: %v", err)
	}
	if savedPair.AccessToken != "new-access-token" {
		t.Errorf("saved access token: got %q, want new-access-token", savedPair.AccessToken)
	}

	// Final response should be 200.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("final response status: got %d, want 200", resp.StatusCode)
	}
}
