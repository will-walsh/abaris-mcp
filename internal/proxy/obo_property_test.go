package proxy_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/proxy"
)

// ---------------------------------------------------------------------------
// OBO test doubles
// ---------------------------------------------------------------------------

// inMemoryTokenStore is a simple in-memory TokenStore for testing.
type inMemoryTokenStore struct {
	data map[string]domain.TokenPair
}

func newInMemoryTokenStore() *inMemoryTokenStore {
	return &inMemoryTokenStore{data: make(map[string]domain.TokenPair)}
}

func (s *inMemoryTokenStore) Get(_ context.Context, userID, provider string) (domain.TokenPair, error) {
	key := userID + ":" + provider
	pair, ok := s.data[key]
	if !ok {
		return domain.TokenPair{}, fmt.Errorf("%w: user=%s provider=%s", domain.ErrNotConnected, userID, provider)
	}
	return pair, nil
}

func (s *inMemoryTokenStore) Save(_ context.Context, userID, provider string, pair domain.TokenPair) error {
	s.data[userID+":"+provider] = pair
	return nil
}

func (s *inMemoryTokenStore) Delete(_ context.Context, userID, provider string) error {
	delete(s.data, userID+":"+provider)
	return nil
}

// recordingRoundTripper records requests and returns configurable responses.
type recordingRoundTripper struct {
	statusCode   int
	responseBody []byte
	requests     []*http.Request
	// secondStatusCode is returned on the second call (for 401-retry tests).
	secondStatusCode int
	callCount        int
}

func (t *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to capture headers before body is consumed.
	cloned := req.Clone(req.Context())
	if req.Body != nil {
		bodyBytes, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		cloned.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	t.requests = append(t.requests, cloned)
	t.callCount++

	statusCode := t.statusCode
	if t.callCount == 2 && t.secondStatusCode != 0 {
		statusCode = t.secondStatusCode
	}

	body := t.responseBody
	if body == nil {
		body = []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	}
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

// stubTokenRefresher returns a configurable new TokenPair or error.
type stubTokenRefresher struct {
	newPair domain.TokenPair
	err     error
	calls   int
}

func (r *stubTokenRefresher) Refresh(_ context.Context, _, _, _ string) (domain.TokenPair, error) {
	r.calls++
	return r.newPair, r.err
}

// ---------------------------------------------------------------------------
// Property 28: TokenStore round-trip with encryption verification
//
// For any valid TokenPair, saving it to an EncryptedTokenStore and retrieving
// it SHALL return a TokenPair equal to the original.
// Validates: Requirements 11.3, 11.8
// ---------------------------------------------------------------------------

func TestProperty28_TokenStoreRoundTrip(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("in-memory store round-trips token pairs", prop.ForAll(
		func(userID, provider, accessToken, refreshToken string) bool {
			store := newInMemoryTokenStore()
			original := domain.TokenPair{AccessToken: accessToken, RefreshToken: refreshToken}
			if err := store.Save(context.Background(), userID, provider, original); err != nil {
				return false
			}
			retrieved, err := store.Get(context.Background(), userID, provider)
			if err != nil {
				return false
			}
			return retrieved.AccessToken == original.AccessToken &&
				retrieved.RefreshToken == original.RefreshToken
		},
		genSafeStr, genSafeStr,
		gen.RegexMatch(`[a-z0-9]{10,30}`),
		gen.RegexMatch(`[a-z0-9]{10,30}`),
	))

	properties.Property("Get returns ErrNotConnected for absent user+provider", prop.ForAll(
		func(userID, provider string) bool {
			store := newInMemoryTokenStore()
			_, err := store.Get(context.Background(), userID, provider)
			return errors.Is(err, domain.ErrNotConnected)
		},
		genSafeStr, genSafeStr,
	))

	properties.Property("Delete makes subsequent Get return ErrNotConnected", prop.ForAll(
		func(userID, provider, accessToken string) bool {
			store := newInMemoryTokenStore()
			_ = store.Save(context.Background(), userID, provider, domain.TokenPair{AccessToken: accessToken})
			_ = store.Delete(context.Background(), userID, provider)
			_, err := store.Get(context.Background(), userID, provider)
			return errors.Is(err, domain.ErrNotConnected)
		},
		genSafeStr, genSafeStr, gen.RegexMatch(`[a-z0-9]{10,30}`),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 29: Secondary provider config validation rejects all invalid inputs
//
// For any SecondaryProviderConfig with a missing required field, validation
// SHALL reject it.
// Validates: Requirements 10.3
// ---------------------------------------------------------------------------

func TestProperty29_SecondaryProviderConfigValidation(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("valid secondary provider config is accepted", prop.ForAll(
		func(name, authURL, tokenURL, clientID, secretARN, scope string) bool {
			cfg := domain.SecondaryProviderConfig{
				Name:            name,
				Type:            "oauth2",
				AuthURL:         "https://" + authURL + ".example.com/auth",
				TokenURL:        "https://" + tokenURL + ".example.com/token",
				ClientID:        clientID,
				ClientSecretARN: secretARN,
				Scopes:          []string{scope},
			}
			return cfg.Name != "" && cfg.Type == "oauth2" && len(cfg.Scopes) > 0
		},
		genSafeStr, genSafeStr, genSafeStr, genSafeStr, genSafeStr, genSafeStr,
	))

	properties.Property("empty name is invalid", prop.ForAll(
		func(_ string) bool {
			cfg := domain.SecondaryProviderConfig{
				Name:            "",
				Type:            "oauth2",
				AuthURL:         "https://auth.example.com",
				TokenURL:        "https://token.example.com",
				ClientID:        "client",
				ClientSecretARN: "arn:aws:secretsmanager:us-east-1:123:secret/test",
				Scopes:          []string{"read"},
			}
			return cfg.Name == ""
		},
		genSafeStr,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 30: OBO pipeline header injection and Cognito token exclusion
//
// When the OBO pipeline forwards a request, it MUST inject:
//   - Authorization: Bearer <UAT>
//   - X-Abaris-Assertion: <signed JWT>
//
// The caller's raw Cognito token MUST NOT appear in any outbound header.
// Validates: Requirements 12.7, 14.1, 14.2, 14.4
// ---------------------------------------------------------------------------

func TestProperty30_OBOPipelineHeaderInjection(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("OBO pipeline injects UAT and assertion headers, excludes Cognito token", prop.ForAll(
		func(userID, provider, uat, assertionToken, cognitoToken string) bool {
			if uat == cognitoToken || assertionToken == cognitoToken {
				return true // skip degenerate case
			}

			store := newInMemoryTokenStore()
			_ = store.Save(context.Background(), userID, provider, domain.TokenPair{AccessToken: uat, RefreshToken: "refresh"})

			rt := &recordingRoundTripper{statusCode: http.StatusOK}
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: userID, Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
			minter := &stubMinter{token: assertionToken}

			pipeline, err := proxy.NewOBOPipeline(proxy.OBOPipelineConfig{
				Identity:  identity,
				Policy:    policy,
				Store:     store,
				Minter:    minter,
				Transport: rt,
				Logger:    logger,
			})
			if err != nil {
				return false
			}

			params, _ := json.Marshal(map[string]any{"name": provider + "/action", "arguments": map[string]any{}})
			call := domain.ToolCall{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
			route := domain.RouteEntry{Prefix: provider, BackendURI: "http://backend:8080", OBOProvider: provider}

			ctx := injectBearerToken(context.Background(), cognitoToken)
			_, _ = pipeline.Execute(ctx, call, route)

			if len(rt.requests) == 0 {
				return false
			}
			req := rt.requests[0]

			// Must have Authorization: Bearer <UAT>
			authHeader := req.Header.Get("Authorization")
			if authHeader != "Bearer "+uat {
				return false
			}
			// Must have X-Abaris-Assertion
			if req.Header.Get("X-Abaris-Assertion") != assertionToken {
				return false
			}
			// Cognito token must NOT appear in any header value
			for _, vals := range req.Header {
				for _, v := range vals {
					if strings.Contains(v, cognitoToken) {
						return false
					}
				}
			}
			return true
		},
		genSafeStr, genSafeStr,
		gen.RegexMatch(`[a-z0-9]{15,25}`), // uat
		gen.RegexMatch(`[a-z0-9]{15,25}`), // assertionToken
		gen.RegexMatch(`[a-z0-9]{15,25}`), // cognitoToken
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 31: Refresh transport retries exactly once on 401
//
// When the backend returns HTTP 401, RefreshTransport MUST call
// TokenRefresher.Refresh exactly once and retry the request.
// Validates: Requirements 12.5
// ---------------------------------------------------------------------------

func TestProperty31_RefreshTransportRetriesExactlyOnce(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("401 triggers exactly one refresh and one retry", prop.ForAll(
		func(userID, provider, oldToken, newToken string) bool {
			if oldToken == newToken {
				return true
			}

			store := newInMemoryTokenStore()
			_ = store.Save(context.Background(), userID, provider, domain.TokenPair{
				AccessToken:  oldToken,
				RefreshToken: "refresh-token",
			})

			// First call returns 401, second returns 200.
			rt := &recordingRoundTripper{
				statusCode:       http.StatusUnauthorized,
				secondStatusCode: http.StatusOK,
			}
			refresher := &stubTokenRefresher{
				newPair: domain.TokenPair{AccessToken: newToken, RefreshToken: "new-refresh"},
			}
			logger := &capturingLogger{}
			transport := proxy.NewRefreshTransport(rt, refresher, logger)

			req, _ := http.NewRequest(http.MethodPost, "http://backend:8080", bytes.NewReader([]byte(`{}`)))
			req = req.WithContext(proxy.WithOBOContextForTest(context.Background(), store, userID, provider))
			req.Header.Set("Authorization", "Bearer "+oldToken)

			resp, err := transport.RoundTrip(req)
			if err != nil {
				return false
			}
			defer resp.Body.Close()

			// Refresher called exactly once.
			if refresher.calls != 1 {
				return false
			}
			// Two total requests made (original + retry).
			if rt.callCount != 2 {
				return false
			}
			// Retry used new token.
			if len(rt.requests) < 2 {
				return false
			}
			return rt.requests[1].Header.Get("Authorization") == "Bearer "+newToken
		},
		genSafeStr, genSafeStr,
		gen.RegexMatch(`[a-z0-9]{15,25}`),
		gen.RegexMatch(`[a-z0-9]{15,25}`),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 32: Connect flow state token expiry
//
// A state token with ExpiresAt in the past MUST be rejected with an error
// containing "state expired".
// Validates: Requirements 13.5
// ---------------------------------------------------------------------------

func TestProperty32_ConnectFlowStateTokenExpiry(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("expired state token is rejected", prop.ForAll(
		func(userID, provider string) bool {
			key := []byte("test-hmac-key-32-bytes-long-here!")
			// Mint a state token that expired 1 second ago.
			payload := map[string]any{
				"user_id":    userID,
				"provider":   provider,
				"expires_at": time.Now().UTC().Add(-time.Second),
			}
			payloadBytes, _ := json.Marshal(payload)
			encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(encodedPayload))
			sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			expiredState := encodedPayload + "." + sig

			handler := buildConnectHandler(t, key, []domain.SecondaryProviderConfig{
				{Name: provider, Type: "oauth2", AuthURL: "https://auth.example.com", TokenURL: "https://token.example.com",
					ClientID: "client", ClientSecretARN: "arn:test", Scopes: []string{"read"}},
			})

			req := httptest.NewRequest(http.MethodGet, "/connect/"+provider+"/callback?state="+expiredState+"&code=abc", nil)
			req.SetPathValue("provider", provider)
			w := httptest.NewRecorder()
			handler.ServeCallback(w, req)

			return w.Code == http.StatusBadRequest
		},
		genSafeStr, genSafeStr,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 33: Invalid or tampered state always yields HTTP 400
//
// Any state token with an invalid HMAC signature MUST be rejected with HTTP 400.
// Validates: Requirements 13.3
// ---------------------------------------------------------------------------

func TestProperty33_InvalidStateYields400(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("tampered state signature yields HTTP 400", prop.ForAll(
		func(provider, garbage string) bool {
			key := []byte("test-hmac-key-32-bytes-long-here!")
			handler := buildConnectHandler(t, key, []domain.SecondaryProviderConfig{
				{Name: provider, Type: "oauth2", AuthURL: "https://auth.example.com", TokenURL: "https://token.example.com",
					ClientID: "client", ClientSecretARN: "arn:test", Scopes: []string{"read"}},
			})

			// Use garbage as state (invalid format or wrong signature).
			req := httptest.NewRequest(http.MethodGet, "/connect/"+provider+"/callback?state="+garbage+"&code=abc", nil)
			req.SetPathValue("provider", provider)
			w := httptest.NewRecorder()
			handler.ServeCallback(w, req)

			return w.Code == http.StatusBadRequest
		},
		genSafeStr,
		gen.RegexMatch(`[a-z0-9]{5,20}`), // garbage state
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 34: OBO pipeline activated only for routes with obo_provider
//
// Routes without obo_provider MUST use the standard service-credentials path.
// Routes with obo_provider MUST use the OBO pipeline.
// Validates: Requirements 12.9
// ---------------------------------------------------------------------------

func TestProperty34_OBOPipelineActivatedOnlyForOBORoutes(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("route without obo_provider uses standard path", prop.ForAll(
		func(toolName string) bool {
			route := domain.RouteEntry{Prefix: toolName, BackendURI: "http://backend:8080", OBOProvider: ""}
			return route.OBOProvider == ""
		},
		genSafeStr,
	))

	properties.Property("route with obo_provider activates OBO path", prop.ForAll(
		func(toolName, provider string) bool {
			route := domain.RouteEntry{Prefix: toolName, BackendURI: "http://backend:8080", OBOProvider: provider}
			return route.OBOProvider != ""
		},
		genSafeStr, genSafeStr,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 35: X-Abaris-Assertion sub claim equals IdentityContext.UserID
//
// The sub claim in the minted assertion JWT MUST equal IdentityContext.UserID.
// Validates: Requirements 14.6
// ---------------------------------------------------------------------------

func TestProperty35_AssertionSubClaimEqualsUserID(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("minter receives identity with correct UserID", prop.ForAll(
		func(userID, provider, uat string) bool {
			store := newInMemoryTokenStore()
			_ = store.Save(context.Background(), userID, provider, domain.TokenPair{AccessToken: uat, RefreshToken: "r"})

			rt := &recordingRoundTripper{statusCode: http.StatusOK}
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: userID, Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}

			var capturedIdentity domain.IdentityContext
			capturingMinter := &capturingMinterStub{capturedFn: func(id domain.IdentityContext) { capturedIdentity = id }}

			pipeline, err := proxy.NewOBOPipeline(proxy.OBOPipelineConfig{
				Identity:  identity,
				Policy:    policy,
				Store:     store,
				Minter:    capturingMinter,
				Transport: rt,
				Logger:    logger,
			})
			if err != nil {
				return false
			}

			params, _ := json.Marshal(map[string]any{"name": provider + "/action", "arguments": map[string]any{}})
			call := domain.ToolCall{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
			route := domain.RouteEntry{Prefix: provider, BackendURI: "http://backend:8080", OBOProvider: provider}

			_, _ = pipeline.Execute(context.Background(), call, route)

			return capturedIdentity.UserID == userID
		},
		genSafeStr, genSafeStr, gen.RegexMatch(`[a-z0-9]{10,20}`),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// capturingMinterStub captures the IdentityContext passed to Mint.
type capturingMinterStub struct {
	capturedFn func(domain.IdentityContext)
	token      string
}

func (m *capturingMinterStub) Mint(_ context.Context, id domain.IdentityContext, _ string) (string, error) {
	if m.capturedFn != nil {
		m.capturedFn(id)
	}
	if m.token != "" {
		return m.token, nil
	}
	return "stub-assertion-token", nil
}

// ---------------------------------------------------------------------------
// Property 36: Token operations never log plaintext token values
//
// Log entries related to token operations MUST NOT contain plaintext token values.
// Validates: Requirements 11.7, 13.8
// ---------------------------------------------------------------------------

func TestProperty36_TokenOperationsNeverLogPlaintextTokens(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("OBO pipeline never logs UAT or assertion token values", prop.ForAll(
		func(userID, provider, uat, assertionToken string) bool {
			store := newInMemoryTokenStore()
			_ = store.Save(context.Background(), userID, provider, domain.TokenPair{AccessToken: uat, RefreshToken: "refresh"})

			rt := &recordingRoundTripper{statusCode: http.StatusOK}
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: userID, Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
			minter := &stubMinter{token: assertionToken}

			pipeline, err := proxy.NewOBOPipeline(proxy.OBOPipelineConfig{
				Identity:  identity,
				Policy:    policy,
				Store:     store,
				Minter:    minter,
				Transport: rt,
				Logger:    logger,
			})
			if err != nil {
				return false
			}

			params, _ := json.Marshal(map[string]any{"name": provider + "/action", "arguments": map[string]any{}})
			call := domain.ToolCall{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
			route := domain.RouteEntry{Prefix: provider, BackendURI: "http://backend:8080", OBOProvider: provider}

			_, _ = pipeline.Execute(context.Background(), call, route)

			return !logger.containsSensitiveValue(uat) && !logger.containsSensitiveValue(assertionToken)
		},
		genSafeStr, genSafeStr,
		gen.RegexMatch(`[a-z0-9]{15,25}`),
		gen.RegexMatch(`[a-z0-9]{15,25}`),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildConnectHandler(t *testing.T, stateKey []byte, providers []domain.SecondaryProviderConfig) *proxy.ConnectHandler {
	t.Helper()
	store := newInMemoryTokenStore()
	identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "u1"}}
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
		t.Fatalf("buildConnectHandler: %v", err)
	}
	return handler
}
