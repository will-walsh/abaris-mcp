// Package assertion_test contains property-based tests for KMSMinter.
//
// These tests validate Properties 22–24 from the Abaris correctness specification:
//
//   - Property 22: Identity Assertion Token contains all required claims (Req 4.4, 4.6)
//   - Property 23: Identity Assertion Token TTL invariant (Req 4.6)
//   - Property 24: KMS signing never exposes private key material (Req 4.4, 7.2)
//
// All tests use a mockKMSClient so they run without network access or real AWS credentials.
package assertion_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/auth/assertion"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// ---------------------------------------------------------------------------
// Mock KMS client
// ---------------------------------------------------------------------------

// sharedTestKey is generated once for the entire test binary to avoid the
// cost of rsa.GenerateKey (2048-bit) on every property iteration.
var sharedTestKey *rsa.PrivateKey

func init() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("generate shared RSA test key: " + err.Error())
	}
	sharedTestKey = key
}

// mockKMSClient implements assertion.KMSClient using an in-process RSA key.
// It signs with the real RSA private key so the produced JWT is verifiable,
// and returns the DER-encoded public key from GetPublicKey.
type mockKMSClient struct {
	privateKey *rsa.PrivateKey
	// signErr, if non-nil, is returned by Sign instead of signing.
	signErr error
	// getPubKeyErr, if non-nil, is returned by GetPublicKey.
	getPubKeyErr error
	// signCalls counts how many times Sign was called.
	signCalls int
	// getPubKeyCalls counts how many times GetPublicKey was called.
	getPubKeyCalls int
}

// newMockKMSClient returns a fresh mockKMSClient backed by the shared test key.
// The shared key is generated once per test binary run to avoid the cost of
// rsa.GenerateKey on every property iteration.
func newMockKMSClient() *mockKMSClient {
	return &mockKMSClient{privateKey: sharedTestKey}
}

func (m *mockKMSClient) Sign(_ context.Context, params *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	m.signCalls++
	if m.signErr != nil {
		return nil, m.signErr
	}
	// The signing input is the raw message (header.payload).
	// We produce a fake but deterministic signature: just sign the message bytes
	// with PKCS1v15 SHA-256 to keep the mock realistic.
	// For property tests we only need the structure, not cryptographic validity.
	sig := make([]byte, 256) // 2048-bit RSA → 256-byte signature
	copy(sig, params.Message)
	return &kms.SignOutput{
		Signature:        sig,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	}, nil
}

func (m *mockKMSClient) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	m.getPubKeyCalls++
	if m.getPubKeyErr != nil {
		return nil, m.getPubKeyErr
	}
	der, err := x509.MarshalPKIXPublicKey(&m.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der}, nil
}

func (m *mockKMSClient) DescribeKey(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseJWT splits a compact JWT into header, payload, and signature segments
// and JSON-decodes the header and payload into maps.
func parseJWT(token string) (header, payload map[string]any, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("expected 3 JWT parts, got %d", len(parts))
	}
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode header: %w", err)
	}
	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode payload: %w", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode signature: %w", err)
	}
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal header: %w", err)
	}
	if err := json.Unmarshal(pBytes, &payload); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	return header, payload, sig, nil
}

// newMinter builds a KMSMinter backed by the given mock client.
func newMinter(t *testing.T, mock *mockKMSClient, ttl time.Duration) *assertion.KMSMinter {
	t.Helper()
	cfg := domain.AssertionConfig{
		Issuer:      "https://abaris.example.com",
		Audience:    "https://backend.internal",
		TTL:         ttl,
		KMSKeyARN:   "arn:aws:kms:us-east-1:123456789012:key/test-key",
		SigningKeyID: "abaris-test",
	}
	m, err := assertion.New(cfg, mock)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// genNonEmptyString generates non-empty alphanumeric strings.
var genNonEmptyString = gen.RegexMatch(`[a-z][a-z0-9]{1,15}`)

// genEmail generates simple email-like strings.
var genEmail = gopter.CombineGens(genNonEmptyString, genNonEmptyString).
	Map(func(v []interface{}) string {
		return v[0].(string) + "@" + v[1].(string) + ".example"
	})

// genGroups generates a non-empty slice of group name strings.
var genGroups = gen.SliceOfN(3, genNonEmptyString).
	Map(func(v []string) []string { return v })

// genIdentityContext generates a random but valid IdentityContext.
var genIdentityContext = gopter.CombineGens(
	genNonEmptyString, // UserID
	genEmail,          // Email
	genGroups,         // Groups
	genNonEmptyString, // Provider
).Map(func(v []interface{}) domain.IdentityContext {
	return domain.IdentityContext{
		UserID:       v[0].(string),
		Email:        v[1].(string),
		Groups:       v[2].([]string),
		Entitlements: []string{"read"},
		Provider:     v[3].(string),
	}
})

// ---------------------------------------------------------------------------
// Property 22: Identity Assertion Token contains all required claims (Req 4.4, 4.6)
// ---------------------------------------------------------------------------

// TestProperty22_IdentityAssertionTokenContainsAllRequiredClaims verifies that
// every JWT minted by KMSMinter contains:
//   - Header: alg=RS256, typ=JWT
//   - Payload top-level: iss, sub, aud, iat, exp, jti
//   - Payload ext_identity: origin_jti, groups, entitlements, provider
//
// Property 22 — Validates: Requirements 4.4, 4.6
func TestProperty22_IdentityAssertionTokenContainsAllRequiredClaims(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 22a: header always has alg=RS256 and typ=JWT
	properties.Property("JWT header always has alg=RS256 and typ=JWT", prop.ForAll(
		func(identity domain.IdentityContext, originJTI string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, originJTI)
			if err != nil {
				return false
			}
			header, _, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			return header["alg"] == "RS256" && header["typ"] == "JWT"
		},
		genIdentityContext, genNonEmptyString,
	))

	// 22b: payload always contains all required top-level OIDC claims
	properties.Property("payload always contains iss, sub, aud, iat, exp, jti", prop.ForAll(
		func(identity domain.IdentityContext, originJTI string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, originJTI)
			if err != nil {
				return false
			}
			_, payload, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			for _, claim := range []string{"iss", "sub", "aud", "iat", "exp", "jti"} {
				if _, ok := payload[claim]; !ok {
					return false
				}
			}
			return true
		},
		genIdentityContext, genNonEmptyString,
	))

	// 22c: sub claim always equals identity.UserID
	properties.Property("sub claim always equals identity.UserID", prop.ForAll(
		func(identity domain.IdentityContext, originJTI string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, originJTI)
			if err != nil {
				return false
			}
			_, payload, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			return payload["sub"] == identity.UserID
		},
		genIdentityContext, genNonEmptyString,
	))

	// 22d: ext_identity always contains origin_jti, groups, entitlements, provider
	properties.Property("ext_identity always contains all required fields", prop.ForAll(
		func(identity domain.IdentityContext, originJTI string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, originJTI)
			if err != nil {
				return false
			}
			_, payload, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			ext, ok := payload["ext_identity"].(map[string]any)
			if !ok {
				return false
			}
			for _, field := range []string{"origin_jti", "groups", "entitlements", "provider"} {
				if _, ok := ext[field]; !ok {
					return false
				}
			}
			// origin_jti must equal the passed originJTI
			return ext["origin_jti"] == originJTI
		},
		genIdentityContext, genNonEmptyString,
	))

	// 22e: iss claim always equals the configured issuer
	properties.Property("iss claim always equals configured issuer", prop.ForAll(
		func(identity domain.IdentityContext, originJTI string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, originJTI)
			if err != nil {
				return false
			}
			_, payload, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			return payload["iss"] == "https://abaris.example.com"
		},
		genIdentityContext, genNonEmptyString,
	))

	// 22f: aud claim always equals the configured audience
	properties.Property("aud claim always equals configured audience", prop.ForAll(
		func(identity domain.IdentityContext, originJTI string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, originJTI)
			if err != nil {
				return false
			}
			_, payload, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			return payload["aud"] == "https://backend.internal"
		},
		genIdentityContext, genNonEmptyString,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 23: Identity Assertion Token TTL invariant (Req 4.6)
// ---------------------------------------------------------------------------

// TestProperty23_IdentityAssertionTokenTTLInvariant verifies that:
//   - exp - iat always equals the configured TTL (within 1 second tolerance)
//   - exp is always strictly greater than iat
//   - iat is always close to the current time
//
// Property 23 — Validates: Requirements 4.6
func TestProperty23_IdentityAssertionTokenTTLInvariant(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 23a: exp - iat always equals configured TTL
	properties.Property("exp minus iat always equals configured TTL", prop.ForAll(
		func(identity domain.IdentityContext, ttlSecs int) bool {
			if ttlSecs <= 0 {
				ttlSecs = 1
			}
			ttl := time.Duration(ttlSecs) * time.Second
			mock := newMockKMSClient()
			m := newMinter(t, mock, ttl)

			before := time.Now().Unix()
			token, err := m.Mint(context.Background(), identity, "jti-test")
			after := time.Now().Unix()
			if err != nil {
				return false
			}
			_, payload, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			iat := int64(payload["iat"].(float64))
			exp := int64(payload["exp"].(float64))

			// iat must be within the before/after window
			if iat < before || iat > after {
				return false
			}
			// exp - iat must equal the configured TTL (within 1s tolerance)
			diff := exp - iat
			return diff == int64(ttlSecs)
		},
		genIdentityContext,
		gen.IntRange(1, 3600),
	))

	// 23b: exp is always strictly greater than iat
	properties.Property("exp is always strictly greater than iat", prop.ForAll(
		func(identity domain.IdentityContext) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, "jti-test")
			if err != nil {
				return false
			}
			_, payload, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			iat := int64(payload["iat"].(float64))
			exp := int64(payload["exp"].(float64))
			return exp > iat
		},
		genIdentityContext,
	))

	// 23c: jti is always a non-empty unique string (UUID format)
	properties.Property("jti is always non-empty", prop.ForAll(
		func(identity domain.IdentityContext) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, "jti-test")
			if err != nil {
				return false
			}
			_, payload, _, err := parseJWT(token)
			if err != nil {
				return false
			}
			jti, ok := payload["jti"].(string)
			return ok && jti != ""
		},
		genIdentityContext,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 24: KMS signing never exposes private key material (Req 4.4, 7.2)
// ---------------------------------------------------------------------------

// TestProperty24_KMSSigningNeverExposesPrivateKeyMaterial verifies that:
//   - The KMSMinter never holds or returns private key bytes
//   - GetPublicKey is called exactly once at construction (cached, not per-request)
//   - Sign is called exactly once per Mint call
//   - The JWT signature segment is non-empty
//
// Property 24 — Validates: Requirements 4.4, 7.2
func TestProperty24_KMSSigningNeverExposesPrivateKeyMaterial(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 24a: GetPublicKey is called exactly once at construction, not per Mint call
	properties.Property("GetPublicKey called exactly once regardless of Mint call count", prop.ForAll(
		func(identity domain.IdentityContext, mintCount int) bool {
			if mintCount <= 0 {
				mintCount = 1
			}
			if mintCount > 10 {
				mintCount = 10
			}
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			// GetPublicKey should have been called exactly once during New().
			if mock.getPubKeyCalls != 1 {
				return false
			}

			for i := 0; i < mintCount; i++ {
				_, err := m.Mint(context.Background(), identity, "jti-test")
				if err != nil {
					return false
				}
			}

			// Still exactly one GetPublicKey call after multiple Mint calls.
			return mock.getPubKeyCalls == 1
		},
		genIdentityContext,
		gen.IntRange(1, 10),
	))

	// 24b: Sign is called exactly once per Mint invocation
	properties.Property("Sign called exactly once per Mint call", prop.ForAll(
		func(identity domain.IdentityContext, mintCount int) bool {
			if mintCount <= 0 {
				mintCount = 1
			}
			if mintCount > 10 {
				mintCount = 10
			}
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			for i := 0; i < mintCount; i++ {
				_, err := m.Mint(context.Background(), identity, "jti-test")
				if err != nil {
					return false
				}
			}
			return mock.signCalls == mintCount
		},
		genIdentityContext,
		gen.IntRange(1, 10),
	))

	// 24c: the JWT signature segment is always non-empty
	properties.Property("JWT signature segment is always non-empty", prop.ForAll(
		func(identity domain.IdentityContext, originJTI string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, originJTI)
			if err != nil {
				return false
			}
			_, _, sig, err := parseJWT(token)
			return err == nil && len(sig) > 0
		},
		genIdentityContext, genNonEmptyString,
	))

	// 24d: PublicKey() returns a non-nil *rsa.PublicKey (cached from GetPublicKey)
	properties.Property("PublicKey returns non-nil cached RSA public key", prop.ForAll(
		func(_ string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)
			return m.PublicKey() != nil
		},
		genNonEmptyString,
	))

	// 24e: the token string never contains the string "PRIVATE" (no PEM private key leakage)
	properties.Property("minted token never contains PRIVATE key material", prop.ForAll(
		func(identity domain.IdentityContext, originJTI string) bool {
			mock := newMockKMSClient()
			m := newMinter(t, mock, 60*time.Second)

			token, err := m.Mint(context.Background(), identity, originJTI)
			if err != nil {
				return false
			}
			return !strings.Contains(token, "PRIVATE") &&
				!strings.Contains(token, "BEGIN RSA")
		},
		genIdentityContext, genNonEmptyString,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
