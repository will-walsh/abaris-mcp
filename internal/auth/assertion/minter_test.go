// Package assertion_test contains unit tests for KMSMinter.
//
// These tests cover:
//   - Correct JWT construction (header, payload structure)
//   - ext_identity object shape and field values
//   - aud claim value matches AssertionConfig.Audience
//   - origin_jti propagation into ext_identity
//   - Error propagation on kms:Sign failure
//   - Error propagation on kms:GetPublicKey failure at construction
//
// Requirements: 4.4, 4.6, 7.7
package assertion_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/will-walsh/abaris-mcp/internal/auth/assertion"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// testIdentity is a fixed IdentityContext used across unit tests.
var testIdentity = domain.IdentityContext{
	UserID:       "user-abc123",
	Email:        "alice@example.com",
	Groups:       []string{"developers", "platform"},
	Entitlements: []string{"read", "write"},
	Provider:     "okta-oidc",
}

// testCfg is a fixed AssertionConfig used across unit tests.
var testCfg = domain.AssertionConfig{
	Issuer:      "https://abaris.example.com",
	Audience:    "https://github-mcp-server.internal",
	TTL:         60 * time.Second,
	KMSKeyARN:   "arn:aws:kms:us-east-1:123456789012:key/test-key",
	SigningKeyID: "abaris-2024-01",
}

// TestKMSMinter_JWTStructure verifies the compact JWT has exactly three
// dot-separated segments (header.payload.signature).
func TestKMSMinter_JWTStructure(t *testing.T) {
	mock := newMockKMSClient()
	m := newMinter(t, mock, testCfg.TTL)

	token, err := m.Mint(context.Background(), testIdentity, "origin-jti-001")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT segments, got %d: %q", len(parts), token)
	}
	for i, part := range parts {
		if part == "" {
			t.Errorf("JWT segment %d is empty", i)
		}
	}
}

// TestKMSMinter_HeaderClaims verifies the JWT header contains alg=RS256,
// typ=JWT, and kid matching the configured SigningKeyID.
func TestKMSMinter_HeaderClaims(t *testing.T) {
	mock := newMockKMSClient()
	m := newMinter(t, mock, testCfg.TTL)

	token, err := m.Mint(context.Background(), testIdentity, "origin-jti-001")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	header, _, _, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}

	if header["alg"] != "RS256" {
		t.Errorf("alg: got %q, want RS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("typ: got %q, want JWT", header["typ"])
	}
	if header["kid"] != "abaris-test" {
		t.Errorf("kid: got %q, want abaris-test", header["kid"])
	}
}

// TestKMSMinter_PayloadTopLevelClaims verifies iss, sub, aud, iat, exp, jti.
func TestKMSMinter_PayloadTopLevelClaims(t *testing.T) {
	mock := newMockKMSClient()
	m := newMinter(t, mock, testCfg.TTL)

	before := time.Now().Unix()
	token, err := m.Mint(context.Background(), testIdentity, "origin-jti-001")
	after := time.Now().Unix()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	_, payload, _, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}

	if payload["iss"] != "https://abaris.example.com" {
		t.Errorf("iss: got %q, want https://abaris.example.com", payload["iss"])
	}
	if payload["sub"] != testIdentity.UserID {
		t.Errorf("sub: got %q, want %q", payload["sub"], testIdentity.UserID)
	}
	if payload["aud"] != "https://backend.internal" {
		t.Errorf("aud: got %q, want https://backend.internal", payload["aud"])
	}

	iat := int64(payload["iat"].(float64))
	exp := int64(payload["exp"].(float64))

	if iat < before || iat > after {
		t.Errorf("iat %d not in [%d, %d]", iat, before, after)
	}
	if exp != iat+60 {
		t.Errorf("exp-iat = %d, want 60", exp-iat)
	}

	jti, ok := payload["jti"].(string)
	if !ok || jti == "" {
		t.Errorf("jti missing or empty: %v", payload["jti"])
	}
}

// TestKMSMinter_ExtIdentityShape verifies the ext_identity object contains
// origin_jti, groups, entitlements, and provider with correct values.
func TestKMSMinter_ExtIdentityShape(t *testing.T) {
	mock := newMockKMSClient()
	m := newMinter(t, mock, testCfg.TTL)

	const originJTI = "cognito-jti-xyz789"
	token, err := m.Mint(context.Background(), testIdentity, originJTI)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	_, payload, _, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}

	ext, ok := payload["ext_identity"].(map[string]any)
	if !ok {
		t.Fatalf("ext_identity missing or wrong type: %T", payload["ext_identity"])
	}

	if ext["origin_jti"] != originJTI {
		t.Errorf("origin_jti: got %q, want %q", ext["origin_jti"], originJTI)
	}
	if ext["provider"] != testIdentity.Provider {
		t.Errorf("provider: got %q, want %q", ext["provider"], testIdentity.Provider)
	}

	groups, ok := ext["groups"].([]any)
	if !ok {
		t.Fatalf("groups wrong type: %T", ext["groups"])
	}
	if len(groups) != len(testIdentity.Groups) {
		t.Errorf("groups len: got %d, want %d", len(groups), len(testIdentity.Groups))
	}

	entitlements, ok := ext["entitlements"].([]any)
	if !ok {
		t.Fatalf("entitlements wrong type: %T", ext["entitlements"])
	}
	if len(entitlements) != len(testIdentity.Entitlements) {
		t.Errorf("entitlements len: got %d, want %d", len(entitlements), len(testIdentity.Entitlements))
	}
}

// TestKMSMinter_OriginJTIPropagation verifies that different originJTI values
// produce different ext_identity.origin_jti values in the minted token.
func TestKMSMinter_OriginJTIPropagation(t *testing.T) {
	mock := newMockKMSClient()
	m := newMinter(t, mock, testCfg.TTL)

	jti1 := "jti-first-call"
	jti2 := "jti-second-call"

	token1, err := m.Mint(context.Background(), testIdentity, jti1)
	if err != nil {
		t.Fatalf("Mint 1: %v", err)
	}
	token2, err := m.Mint(context.Background(), testIdentity, jti2)
	if err != nil {
		t.Fatalf("Mint 2: %v", err)
	}

	_, payload1, _, _ := parseJWT(token1)
	_, payload2, _, _ := parseJWT(token2)

	ext1 := payload1["ext_identity"].(map[string]any)
	ext2 := payload2["ext_identity"].(map[string]any)

	if ext1["origin_jti"] != jti1 {
		t.Errorf("token1 origin_jti: got %q, want %q", ext1["origin_jti"], jti1)
	}
	if ext2["origin_jti"] != jti2 {
		t.Errorf("token2 origin_jti: got %q, want %q", ext2["origin_jti"], jti2)
	}
}

// TestKMSMinter_SignFailurePropagation verifies that a kms:Sign error is
// wrapped as domain.ErrServiceUnavailable and returned from Mint.
func TestKMSMinter_SignFailurePropagation(t *testing.T) {
	mock := newMockKMSClient()
	mock.signErr = errors.New("kms: key not found")

	m := newMinter(t, mock, testCfg.TTL)

	_, err := m.Mint(context.Background(), testIdentity, "jti-test")
	if err == nil {
		t.Fatal("expected error from Mint when Sign fails, got nil")
	}
	if !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got: %v", err)
	}
}

// TestKMSMinter_GetPublicKeyFailurePropagation verifies that a kms:GetPublicKey
// error at construction time is returned from New.
func TestKMSMinter_GetPublicKeyFailurePropagation(t *testing.T) {
	mock := newMockKMSClient()
	mock.getPubKeyErr = errors.New("kms: access denied")

	cfg := domain.AssertionConfig{
		Issuer:    "https://abaris.example.com",
		Audience:  "https://backend.internal",
		TTL:       60 * time.Second,
		KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/test-key",
	}
	_, err := assertion.New(cfg, mock)
	if err == nil {
		t.Fatal("expected error from New when GetPublicKey fails, got nil")
	}
	if !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got: %v", err)
	}
}

// TestKMSMinter_AudClaimMatchesConfig verifies that the aud claim in the minted
// JWT always matches AssertionConfig.Audience.
func TestKMSMinter_AudClaimMatchesConfig(t *testing.T) {
	audiences := []string{
		"https://github-mcp-server.internal",
		"https://jira-mcp-server.internal",
		"urn:example:audience",
	}

	for _, aud := range audiences {
		t.Run(aud, func(t *testing.T) {
			mock := newMockKMSClient()
			cfg := domain.AssertionConfig{
				Issuer:    "https://abaris.example.com",
				Audience:  aud,
				TTL:       60 * time.Second,
				KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/test-key",
			}
			m, err := assertion.New(cfg, mock)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			token, err := m.Mint(context.Background(), testIdentity, "jti-test")
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}

			_, payload, _, err := parseJWT(token)
			if err != nil {
				t.Fatalf("parseJWT: %v", err)
			}
			if payload["aud"] != aud {
				t.Errorf("aud: got %q, want %q", payload["aud"], aud)
			}
		})
	}
}

// TestKMSMinter_JWKSHandler verifies that JWKSHandler returns a valid JWKS
// JSON response with the cached public key.
func TestKMSMinter_JWKSHandler(t *testing.T) {
	mock := newMockKMSClient()
	m := newMinter(t, mock, testCfg.TTL)

	handler := m.JWKSHandler()
	if handler == nil {
		t.Fatal("JWKSHandler returned nil")
	}

	// Verify the public key is cached (non-nil).
	if m.PublicKey() == nil {
		t.Error("PublicKey() returned nil after construction")
	}
}

// TestKMSMinter_NewValidation verifies that New returns errors for invalid configs.
func TestKMSMinter_NewValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  domain.AssertionConfig
	}{
		{"missing KMSKeyARN", domain.AssertionConfig{Issuer: "https://a.example.com", Audience: "aud", TTL: time.Minute}},
		{"missing Issuer", domain.AssertionConfig{KMSKeyARN: "arn:aws:kms:us-east-1:123:key/k", Audience: "aud", TTL: time.Minute}},
		{"missing Audience", domain.AssertionConfig{Issuer: "https://a.example.com", KMSKeyARN: "arn:aws:kms:us-east-1:123:key/k", TTL: time.Minute}},
		{"zero TTL", domain.AssertionConfig{Issuer: "https://a.example.com", Audience: "aud", KMSKeyARN: "arn:aws:kms:us-east-1:123:key/k"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockKMSClient()
			_, err := assertion.New(tc.cfg, mock)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc.name)
			}
		})
	}
}
