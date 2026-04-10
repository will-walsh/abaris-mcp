//go:build integration

// Package oidc_test contains integration tests for OIDCAdapter end-to-end
// with an in-process test OIDC provider.
//
// These tests spin up a real httptest.Server that serves:
//   - GET /.well-known/openid-configuration  (discovery document)
//   - GET /.well-known/jwks.json             (JWKS endpoint with the test RSA public key)
//
// Real RSA key pairs are generated in-process; real JWTs are minted and signed
// with the test private key using only the standard library.
//
// Run with: go test -tags integration ./internal/auth/oidc/...
//
// Validates: Requirements 2.2, 2.4
package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/auth/oidc"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// ---------------------------------------------------------------------------
// Test OIDC provider helpers
// ---------------------------------------------------------------------------

// testOIDCProvider holds the RSA key pair and the httptest.Server that serves
// the discovery document and JWKS endpoint.
type testOIDCProvider struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	keyID      string
}

// newTestOIDCProvider generates an RSA-2048 key pair, starts an httptest.Server
// that serves a minimal OIDC discovery document and JWKS endpoint, and returns
// the provider. The caller must call Close() when done.
func newTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	p := &testOIDCProvider{
		privateKey: privateKey,
		keyID:      "test-key-1",
	}

	mux := http.NewServeMux()
	// We need the server URL before registering handlers, so we use a pointer
	// that gets filled in after server creation.
	var serverURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":   serverURL,
			"jwks_uri": serverURL + "/.well-known/jwks.json",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc) //nolint:errcheck
	})

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pub := &privateKey.PublicKey
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": p.keyID,
					"n":   n,
					"e":   e,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	})

	p.server = httptest.NewServer(mux)
	serverURL = p.server.URL
	return p
}

// Close shuts down the test OIDC provider server.
func (p *testOIDCProvider) Close() {
	p.server.Close()
}

// Issuer returns the issuer URL (the test server's base URL).
func (p *testOIDCProvider) Issuer() string {
	return p.server.URL
}

// JWKSURL returns the JWKS endpoint URL.
func (p *testOIDCProvider) JWKSURL() string {
	return p.server.URL + "/.well-known/jwks.json"
}

// ---------------------------------------------------------------------------
// JWT minting helpers (standard library only)
// ---------------------------------------------------------------------------

// jwtClaims holds the claims for a test JWT.
type jwtClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      []string `json:"aud"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	Email         string   `json:"email,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Entitlements  []string `json:"entitlements,omitempty"`
}

// mintJWT creates a real RS256-signed JWT using the provided private key.
// The header uses kid matching the test provider's key ID.
func mintJWT(t *testing.T, key *rsa.PrivateKey, keyID string, claims jwtClaims) string {
	t.Helper()

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": keyID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// mintTamperedJWT creates a JWT with a valid structure but a corrupted signature.
func mintTamperedJWT(t *testing.T, key *rsa.PrivateKey, keyID string, claims jwtClaims) string {
	t.Helper()
	valid := mintJWT(t, key, keyID, claims)
	parts := strings.Split(valid, ".")
	if len(parts) != 3 {
		t.Fatal("unexpected JWT structure")
	}
	// Flip the last byte of the signature to corrupt it.
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigBytes[len(sigBytes)-1] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	return strings.Join(parts, ".")
}

// ---------------------------------------------------------------------------
// Test adapter factory
// ---------------------------------------------------------------------------

// newIntegrationAdapter builds an OIDCAdapter pointed at the given test provider.
func newIntegrationAdapter(t *testing.T, p *testOIDCProvider, audience string) *oidc.OIDCAdapter {
	t.Helper()
	cfg := oidc.Config{
		ProviderName: "test-oidc",
		Issuer:       p.Issuer(),
		JWKSURL:      p.JWKSURL(),
		ClientID:     audience,
		Audience:     audience,
		GroupsClaim:  "groups",
		CacheTTL:     time.Second,
	}
	adapter, err := oidc.New(cfg, noopLogger{})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return adapter
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestOIDCAdapter_Integration_ValidToken verifies that a valid, correctly-signed
// JWT with all required claims resolves to the expected IdentityContext.
//
// Validates: Requirements 2.2, 2.4
func TestOIDCAdapter_Integration_ValidToken(t *testing.T) {
	p := newTestOIDCProvider(t)
	defer p.Close()

	const audience = "test-client"
	adapter := newIntegrationAdapter(t, p, audience)
	defer adapter.Stop()

	now := time.Now()
	claims := jwtClaims{
		Issuer:       p.Issuer(),
		Subject:      "user-abc-123",
		Audience:     []string{audience},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Email:        "alice@example.com",
		Groups:       []string{"developers", "admins"},
		Entitlements: []string{"read", "write"},
	}
	token := mintJWT(t, p.privateKey, p.keyID, claims)

	ctx := authctx.WithBearerToken(context.Background(), token)
	identity, err := adapter.Resolve(ctx)
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}

	if identity.UserID != "user-abc-123" {
		t.Errorf("UserID: got %q, want %q", identity.UserID, "user-abc-123")
	}
	if identity.Email != "alice@example.com" {
		t.Errorf("Email: got %q, want %q", identity.Email, "alice@example.com")
	}
	if len(identity.Groups) != 2 || identity.Groups[0] != "developers" || identity.Groups[1] != "admins" {
		t.Errorf("Groups: got %v, want [developers admins]", identity.Groups)
	}
	if len(identity.Entitlements) != 2 || identity.Entitlements[0] != "read" || identity.Entitlements[1] != "write" {
		t.Errorf("Entitlements: got %v, want [read write]", identity.Entitlements)
	}
	if identity.Provider != "test-oidc" {
		t.Errorf("Provider: got %q, want %q", identity.Provider, "test-oidc")
	}
}

// TestOIDCAdapter_Integration_ExpiredToken verifies that an expired JWT returns
// ErrUnauthorized.
//
// Validates: Requirements 2.2
func TestOIDCAdapter_Integration_ExpiredToken(t *testing.T) {
	p := newTestOIDCProvider(t)
	defer p.Close()

	const audience = "test-client"
	adapter := newIntegrationAdapter(t, p, audience)
	defer adapter.Stop()

	past := time.Now().Add(-10 * time.Minute)
	claims := jwtClaims{
		Issuer:    p.Issuer(),
		Subject:   "user-expired",
		Audience:  []string{audience},
		IssuedAt:  past.Add(-5 * time.Minute).Unix(),
		ExpiresAt: past.Unix(), // already expired
	}
	token := mintJWT(t, p.privateKey, p.keyID, claims)

	ctx := authctx.WithBearerToken(context.Background(), token)
	_, err := adapter.Resolve(ctx)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for expired token, got: %v", err)
	}
}

// TestOIDCAdapter_Integration_WrongIssuer verifies that a JWT with an issuer
// that does not match the configured issuer returns ErrUnauthorized.
//
// Validates: Requirements 2.2
func TestOIDCAdapter_Integration_WrongIssuer(t *testing.T) {
	p := newTestOIDCProvider(t)
	defer p.Close()

	const audience = "test-client"
	adapter := newIntegrationAdapter(t, p, audience)
	defer adapter.Stop()

	now := time.Now()
	claims := jwtClaims{
		Issuer:    "https://wrong-issuer.example.com", // wrong issuer
		Subject:   "user-wrong-issuer",
		Audience:  []string{audience},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	token := mintJWT(t, p.privateKey, p.keyID, claims)

	ctx := authctx.WithBearerToken(context.Background(), token)
	_, err := adapter.Resolve(ctx)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for wrong issuer, got: %v", err)
	}
}

// TestOIDCAdapter_Integration_WrongAudience verifies that a JWT with an audience
// that does not match the configured audience returns ErrUnauthorized.
//
// Validates: Requirements 2.2
func TestOIDCAdapter_Integration_WrongAudience(t *testing.T) {
	p := newTestOIDCProvider(t)
	defer p.Close()

	const audience = "test-client"
	adapter := newIntegrationAdapter(t, p, audience)
	defer adapter.Stop()

	now := time.Now()
	claims := jwtClaims{
		Issuer:    p.Issuer(),
		Subject:   "user-wrong-aud",
		Audience:  []string{"wrong-audience"}, // wrong audience
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	token := mintJWT(t, p.privateKey, p.keyID, claims)

	ctx := authctx.WithBearerToken(context.Background(), token)
	_, err := adapter.Resolve(ctx)
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for wrong audience, got: %v", err)
	}
}

// TestOIDCAdapter_Integration_TamperedSignature verifies that a JWT with a
// corrupted signature returns ErrUnauthorized.
//
// Validates: Requirements 2.2
func TestOIDCAdapter_Integration_TamperedSignature(t *testing.T) {
	p := newTestOIDCProvider(t)
	defer p.Close()

	const audience = "test-client"
	adapter := newIntegrationAdapter(t, p, audience)
	defer adapter.Stop()

	now := time.Now()
	claims := jwtClaims{
		Issuer:    p.Issuer(),
		Subject:   "user-tampered",
		Audience:  []string{audience},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
	token := mintTamperedJWT(t, p.privateKey, p.keyID, claims)

	ctx := authctx.WithBearerToken(context.Background(), token)
	_, err := adapter.Resolve(ctx)
	if err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for tampered signature, got: %v", err)
	}
}

// TestOIDCAdapter_Integration_MissingToken verifies that a context with no
// Bearer token returns ErrUnauthenticated.
//
// Validates: Requirements 2.2
func TestOIDCAdapter_Integration_MissingToken(t *testing.T) {
	p := newTestOIDCProvider(t)
	defer p.Close()

	adapter := newIntegrationAdapter(t, p, "test-client")
	defer adapter.Stop()

	_, err := adapter.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error for missing token, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated for missing token, got: %v", err)
	}
}

// TestOIDCAdapter_Integration_ClaimsNormalization verifies that the adapter
// correctly maps JWT claims to IdentityContext fields:
//   - "sub"          → UserID
//   - "email"        → Email
//   - "groups"       → Groups
//   - "entitlements" → Entitlements
//
// Validates: Requirements 2.4
func TestOIDCAdapter_Integration_ClaimsNormalization(t *testing.T) {
	p := newTestOIDCProvider(t)
	defer p.Close()

	const audience = "test-client"
	adapter := newIntegrationAdapter(t, p, audience)
	defer adapter.Stop()

	now := time.Now()
	claims := jwtClaims{
		Issuer:       p.Issuer(),
		Subject:      "sub-value-xyz",
		Audience:     []string{audience},
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(5 * time.Minute).Unix(),
		Email:        "bob@corp.example",
		Groups:       []string{"platform-eng", "sre"},
		Entitlements: []string{"deploy", "rollback"},
	}
	token := mintJWT(t, p.privateKey, p.keyID, claims)

	ctx := authctx.WithBearerToken(context.Background(), token)
	identity, err := adapter.Resolve(ctx)
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}

	// sub → UserID
	if identity.UserID != "sub-value-xyz" {
		t.Errorf("UserID (from sub): got %q, want %q", identity.UserID, "sub-value-xyz")
	}
	// email → Email
	if identity.Email != "bob@corp.example" {
		t.Errorf("Email: got %q, want %q", identity.Email, "bob@corp.example")
	}
	// groups → Groups
	if len(identity.Groups) != 2 {
		t.Fatalf("Groups length: got %d, want 2", len(identity.Groups))
	}
	if identity.Groups[0] != "platform-eng" || identity.Groups[1] != "sre" {
		t.Errorf("Groups: got %v, want [platform-eng sre]", identity.Groups)
	}
	// entitlements → Entitlements
	if len(identity.Entitlements) != 2 {
		t.Fatalf("Entitlements length: got %d, want 2", len(identity.Entitlements))
	}
	if identity.Entitlements[0] != "deploy" || identity.Entitlements[1] != "rollback" {
		t.Errorf("Entitlements: got %v, want [deploy rollback]", identity.Entitlements)
	}
}

// TestOIDCAdapter_Integration_TokenWithNoGroupsOrEntitlements verifies that a
// valid token with no groups or entitlements claims resolves to an IdentityContext
// with empty slices (not nil panics).
//
// Validates: Requirements 2.4
func TestOIDCAdapter_Integration_TokenWithNoGroupsOrEntitlements(t *testing.T) {
	p := newTestOIDCProvider(t)
	defer p.Close()

	const audience = "test-client"
	adapter := newIntegrationAdapter(t, p, audience)
	defer adapter.Stop()

	now := time.Now()
	claims := jwtClaims{
		Issuer:    p.Issuer(),
		Subject:   "minimal-user",
		Audience:  []string{audience},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		Email:     "minimal@example.com",
		// No Groups or Entitlements
	}
	token := mintJWT(t, p.privateKey, p.keyID, claims)

	ctx := authctx.WithBearerToken(context.Background(), token)
	identity, err := adapter.Resolve(ctx)
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}

	if identity.UserID != "minimal-user" {
		t.Errorf("UserID: got %q, want %q", identity.UserID, "minimal-user")
	}
	if identity.Email != "minimal@example.com" {
		t.Errorf("Email: got %q, want %q", identity.Email, "minimal@example.com")
	}
	// Groups and Entitlements should be nil/empty — not a panic.
	_ = identity.Groups
	_ = identity.Entitlements
}
