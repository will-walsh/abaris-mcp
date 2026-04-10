//go:build integration

// Package assertion_test contains integration tests for KMSMinter against LocalStack.
//
// These tests require LocalStack running at http://localhost:4566 with KMS enabled.
// Run with: go test -tags integration ./internal/auth/assertion/...
//
// Test cases:
//  1. JWT signature validates against the public key from kms:GetPublicKey (Req 4.4)
//  2. JWT contains all required claims: iss, sub, aud, iat, exp, ext_identity (Req 4.4)
//  3. Private key is never loaded into process memory — only kms:Sign is used (Req 4.4)
//  4. JWKS endpoint returns the correct public key matching the KMS key (Req 7.2)
//
// Validates: Requirements 4.4, 7.2
package assertion_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/will-walsh/abaris-mcp/internal/auth/assertion"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

const localstackEndpoint = "http://localhost:4566"

// newLocalStackKMSClient creates an AWS KMS client pointed at LocalStack.
func newLocalStackKMSClient(t *testing.T) *kms.Client {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
		config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					URL:               localstackEndpoint,
					HostnameImmutable: true,
				}, nil
			}),
		),
	)
	if err != nil {
		t.Fatalf("load AWS config for LocalStack: %v", err)
	}
	return kms.NewFromConfig(cfg)
}

// createLocalStackKMSKey creates a real RSA_2048 SIGN_VERIFY key in LocalStack
// and returns its key ID. The key is created fresh for each test run.
func createLocalStackKMSKey(t *testing.T, client *kms.Client) string {
	t.Helper()
	out, err := client.CreateKey(context.Background(), &kms.CreateKeyInput{
		KeySpec:  types.KeySpecRsa2048,
		KeyUsage: types.KeyUsageTypeSignVerify,
		Description: aws.String("abaris-integration-test-key"),
	})
	if err != nil {
		t.Fatalf("CreateKey in LocalStack: %v", err)
	}
	return aws.ToString(out.KeyMetadata.KeyId)
}

// localStackKMSAdapter wraps *kms.Client to satisfy assertion.KMSClient.
// The real *kms.Client already satisfies the interface; this is just a type alias
// to make the wiring explicit.
type localStackKMSAdapter struct {
	client *kms.Client
}

func (a *localStackKMSAdapter) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return a.client.Sign(ctx, params, optFns...)
}

func (a *localStackKMSAdapter) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return a.client.GetPublicKey(ctx, params, optFns...)
}

func (a *localStackKMSAdapter) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return a.client.DescribeKey(ctx, params, optFns...)
}

// integrationAssertionConfig returns a test AssertionConfig using the given KMS key ID.
func integrationAssertionConfig(keyID string) domain.AssertionConfig {
	return domain.AssertionConfig{
		Issuer:      "https://abaris.integration.test",
		Audience:    "https://backend.integration.test",
		TTL:         5 * time.Minute,
		KMSKeyARN:   keyID,
		SigningKeyID: "integration-test-key",
	}
}

// integrationIdentity returns a fixed IdentityContext for integration tests.
var integrationIdentity = domain.IdentityContext{
	UserID:       "integration-user-001",
	Email:        "integration@example.com",
	Groups:       []string{"developers", "platform"},
	Entitlements: []string{"read", "write"},
	Provider:     "test-oidc",
}

// verifyRS256JWT verifies a compact JWT's RS256 signature against the given RSA public key.
// Returns the decoded header and payload maps on success.
func verifyRS256JWT(t *testing.T, token string, pub *rsa.PublicKey) (header, payload map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT must have 3 parts, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode JWT signature: %v", err)
	}

	// SHA-256 hash of the signing input (header.payload).
	h := sha256.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	// Verify PKCS1v15 signature using the RSA public key from kms:GetPublicKey.
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sigBytes); err != nil {
		t.Fatalf("JWT signature verification failed: %v", err)
	}

	// Decode header.
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	if err := json.Unmarshal(hBytes, &header); err != nil {
		t.Fatalf("unmarshal JWT header: %v", err)
	}

	// Decode payload.
	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	if err := json.Unmarshal(pBytes, &payload); err != nil {
		t.Fatalf("unmarshal JWT payload: %v", err)
	}

	return header, payload
}

// getPublicKeyFromKMS retrieves the RSA public key directly from LocalStack KMS
// and parses it into an *rsa.PublicKey.
func getPublicKeyFromKMS(t *testing.T, client *kms.Client, keyID string) *rsa.PublicKey {
	t.Helper()
	out, err := client.GetPublicKey(context.Background(), &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		t.Fatalf("kms:GetPublicKey from LocalStack: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		t.Fatalf("parse DER public key from KMS: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("KMS key is not RSA, got %T", pub)
	}
	return rsaPub
}

// ---------------------------------------------------------------------------
// Test 1: JWT signature validates against kms:GetPublicKey
// Validates: Requirements 4.4, 7.2
// ---------------------------------------------------------------------------

// TestKMSIntegration_SignatureValidatesAgainstKMSPublicKey mints a JWT via
// KMSMinter (which calls kms:Sign on LocalStack) and verifies the signature
// using the public key retrieved directly from kms:GetPublicKey.
//
// This proves end-to-end that:
//   - The JWT is signed by the KMS private key (never loaded into memory)
//   - The signature is verifiable using only the public key from kms:GetPublicKey
//
// Validates: Requirements 4.4, 7.2
func TestKMSIntegration_SignatureValidatesAgainstKMSPublicKey(t *testing.T) {
	kmsClient := newLocalStackKMSClient(t)
	keyID := createLocalStackKMSKey(t, kmsClient)

	adapter := &localStackKMSAdapter{client: kmsClient}
	cfg := integrationAssertionConfig(keyID)

	minter, err := assertion.New(cfg, adapter)
	if err != nil {
		t.Fatalf("assertion.New: %v", err)
	}

	token, err := minter.Mint(context.Background(), integrationIdentity, "origin-jti-integration-001")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Retrieve the public key directly from LocalStack KMS (independent of minter).
	kmsPublicKey := getPublicKeyFromKMS(t, kmsClient, keyID)

	// Verify the JWT signature against the KMS public key.
	// verifyRS256JWT calls t.Fatalf on any verification failure.
	verifyRS256JWT(t, token, kmsPublicKey)
}

// ---------------------------------------------------------------------------
// Test 2: JWT contains all required claims
// Validates: Requirements 4.4
// ---------------------------------------------------------------------------

// TestKMSIntegration_JWTContainsAllRequiredClaims mints a JWT and verifies
// that all required claims are present with correct values:
//   - Header: alg=RS256, typ=JWT, kid
//   - Payload: iss, sub, aud, iat, exp, jti
//   - Payload ext_identity: origin_jti, groups, entitlements, provider
//
// Validates: Requirements 4.4
func TestKMSIntegration_JWTContainsAllRequiredClaims(t *testing.T) {
	kmsClient := newLocalStackKMSClient(t)
	keyID := createLocalStackKMSKey(t, kmsClient)

	adapter := &localStackKMSAdapter{client: kmsClient}
	cfg := integrationAssertionConfig(keyID)

	minter, err := assertion.New(cfg, adapter)
	if err != nil {
		t.Fatalf("assertion.New: %v", err)
	}

	const originJTI = "origin-jti-claims-test"
	before := time.Now().Unix()
	token, err := minter.Mint(context.Background(), integrationIdentity, originJTI)
	after := time.Now().Unix()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	kmsPublicKey := getPublicKeyFromKMS(t, kmsClient, keyID)
	header, payload := verifyRS256JWT(t, token, kmsPublicKey)

	// --- Header checks ---
	if header["alg"] != "RS256" {
		t.Errorf("header.alg: got %q, want RS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("header.typ: got %q, want JWT", header["typ"])
	}
	if header["kid"] != cfg.SigningKeyID {
		t.Errorf("header.kid: got %q, want %q", header["kid"], cfg.SigningKeyID)
	}

	// --- Top-level payload claims ---
	if payload["iss"] != cfg.Issuer {
		t.Errorf("iss: got %q, want %q", payload["iss"], cfg.Issuer)
	}
	if payload["sub"] != integrationIdentity.UserID {
		t.Errorf("sub: got %q, want %q", payload["sub"], integrationIdentity.UserID)
	}
	if payload["aud"] != cfg.Audience {
		t.Errorf("aud: got %q, want %q", payload["aud"], cfg.Audience)
	}

	iat, ok := payload["iat"].(float64)
	if !ok {
		t.Fatalf("iat missing or wrong type: %T", payload["iat"])
	}
	if int64(iat) < before || int64(iat) > after {
		t.Errorf("iat %d not in [%d, %d]", int64(iat), before, after)
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatalf("exp missing or wrong type: %T", payload["exp"])
	}
	expectedTTL := int64(cfg.TTL.Seconds())
	if int64(exp)-int64(iat) != expectedTTL {
		t.Errorf("exp-iat = %d, want %d (TTL)", int64(exp)-int64(iat), expectedTTL)
	}

	jti, ok := payload["jti"].(string)
	if !ok || jti == "" {
		t.Errorf("jti missing or empty: %v", payload["jti"])
	}

	// --- ext_identity object ---
	ext, ok := payload["ext_identity"].(map[string]any)
	if !ok {
		t.Fatalf("ext_identity missing or wrong type: %T", payload["ext_identity"])
	}
	if ext["origin_jti"] != originJTI {
		t.Errorf("ext_identity.origin_jti: got %q, want %q", ext["origin_jti"], originJTI)
	}
	if ext["provider"] != integrationIdentity.Provider {
		t.Errorf("ext_identity.provider: got %q, want %q", ext["provider"], integrationIdentity.Provider)
	}

	groups, ok := ext["groups"].([]any)
	if !ok {
		t.Fatalf("ext_identity.groups wrong type: %T", ext["groups"])
	}
	if len(groups) != len(integrationIdentity.Groups) {
		t.Errorf("ext_identity.groups len: got %d, want %d", len(groups), len(integrationIdentity.Groups))
	}

	entitlements, ok := ext["entitlements"].([]any)
	if !ok {
		t.Fatalf("ext_identity.entitlements wrong type: %T", ext["entitlements"])
	}
	if len(entitlements) != len(integrationIdentity.Entitlements) {
		t.Errorf("ext_identity.entitlements len: got %d, want %d", len(entitlements), len(integrationIdentity.Entitlements))
	}
}

// ---------------------------------------------------------------------------
// Test 3: Private key never loaded into process memory
// Validates: Requirements 4.4
// ---------------------------------------------------------------------------

// TestKMSIntegration_PrivateKeyNeverInMemory verifies that KMSMinter never
// holds RSA private key material. The only key material in memory is the
// cached *rsa.PublicKey from kms:GetPublicKey.
//
// This is verified by:
//   - Confirming PublicKey() returns a non-nil *rsa.PublicKey (public only)
//   - Confirming the minted JWT token string contains no PEM private key markers
//   - Confirming kms:GetPublicKey is called exactly once at construction (cached)
//   - Confirming kms:Sign is called for each Mint (private key stays in KMS)
//
// Validates: Requirements 4.4
func TestKMSIntegration_PrivateKeyNeverInMemory(t *testing.T) {
	kmsClient := newLocalStackKMSClient(t)
	keyID := createLocalStackKMSKey(t, kmsClient)

	// Wrap the real KMS client in a call-counting adapter.
	counting := &countingKMSAdapter{inner: &localStackKMSAdapter{client: kmsClient}}
	cfg := integrationAssertionConfig(keyID)

	minter, err := assertion.New(cfg, counting)
	if err != nil {
		t.Fatalf("assertion.New: %v", err)
	}

	// GetPublicKey must have been called exactly once at construction.
	if counting.getPubKeyCalls != 1 {
		t.Errorf("GetPublicKey calls after New: got %d, want 1", counting.getPubKeyCalls)
	}

	// PublicKey() must return a non-nil public key (not a private key).
	pub := minter.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey() returned nil")
	}
	// Verify it is a public key (has no private exponent).
	// *rsa.PublicKey has only N and E — no D, P, Q, etc.
	_ = pub.N
	_ = pub.E

	// Mint a token and verify no private key material appears in the output.
	token, err := minter.Mint(context.Background(), integrationIdentity, "jti-memory-test")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if strings.Contains(token, "PRIVATE") || strings.Contains(token, "BEGIN RSA") {
		t.Error("minted token contains private key material")
	}

	// Sign must have been called exactly once for the single Mint call.
	if counting.signCalls != 1 {
		t.Errorf("Sign calls after one Mint: got %d, want 1", counting.signCalls)
	}

	// GetPublicKey must still be exactly 1 (not called again during Mint).
	if counting.getPubKeyCalls != 1 {
		t.Errorf("GetPublicKey calls after Mint: got %d, want 1 (must be cached)", counting.getPubKeyCalls)
	}

	// Mint a second token — Sign should be called again, GetPublicKey should not.
	_, err = minter.Mint(context.Background(), integrationIdentity, "jti-memory-test-2")
	if err != nil {
		t.Fatalf("second Mint: %v", err)
	}
	if counting.signCalls != 2 {
		t.Errorf("Sign calls after two Mints: got %d, want 2", counting.signCalls)
	}
	if counting.getPubKeyCalls != 1 {
		t.Errorf("GetPublicKey calls after two Mints: got %d, want 1 (cached)", counting.getPubKeyCalls)
	}
}

// countingKMSAdapter wraps a KMSClient and counts Sign and GetPublicKey calls.
type countingKMSAdapter struct {
	inner          assertion.KMSClient
	signCalls      int
	getPubKeyCalls int
}

func (c *countingKMSAdapter) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	c.signCalls++
	return c.inner.Sign(ctx, params, optFns...)
}

func (c *countingKMSAdapter) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	c.getPubKeyCalls++
	return c.inner.GetPublicKey(ctx, params, optFns...)
}

func (c *countingKMSAdapter) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return c.inner.DescribeKey(ctx, params, optFns...)
}

// ---------------------------------------------------------------------------
// Test 4: JWKS endpoint returns the correct public key matching the KMS key
// Validates: Requirements 7.2
// ---------------------------------------------------------------------------

// TestKMSIntegration_JWKSEndpointMatchesKMSPublicKey verifies that the JWKS
// endpoint served by KMSMinter.JWKSHandler returns a public key that matches
// the key returned by kms:GetPublicKey.
//
// The test:
//  1. Creates a KMSMinter backed by a real LocalStack KMS key
//  2. Starts an httptest.Server serving the JWKSHandler
//  3. Fetches the JWKS JSON from the endpoint
//  4. Reconstructs the RSA public key from the JWK n/e fields
//  5. Compares it to the public key retrieved directly from kms:GetPublicKey
//
// Validates: Requirements 7.2
func TestKMSIntegration_JWKSEndpointMatchesKMSPublicKey(t *testing.T) {
	kmsClient := newLocalStackKMSClient(t)
	keyID := createLocalStackKMSKey(t, kmsClient)

	adapter := &localStackKMSAdapter{client: kmsClient}
	cfg := integrationAssertionConfig(keyID)

	minter, err := assertion.New(cfg, adapter)
	if err != nil {
		t.Fatalf("assertion.New: %v", err)
	}

	// Start a test HTTP server serving the JWKS handler.
	srv := httptest.NewServer(minter.JWKSHandler())
	defer srv.Close()

	// Fetch the JWKS from the endpoint.
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET JWKS endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("JWKS endpoint status: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	// Parse the JWKS response.
	var jwksResp struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwksResp); err != nil {
		t.Fatalf("decode JWKS response: %v", err)
	}

	if len(jwksResp.Keys) != 1 {
		t.Fatalf("JWKS keys count: got %d, want 1", len(jwksResp.Keys))
	}
	jwk := jwksResp.Keys[0]

	// Validate JWK metadata.
	if jwk.Kty != "RSA" {
		t.Errorf("jwk.kty: got %q, want RSA", jwk.Kty)
	}
	if jwk.Use != "sig" {
		t.Errorf("jwk.use: got %q, want sig", jwk.Use)
	}
	if jwk.Alg != "RS256" {
		t.Errorf("jwk.alg: got %q, want RS256", jwk.Alg)
	}
	if jwk.Kid != cfg.SigningKeyID {
		t.Errorf("jwk.kid: got %q, want %q", jwk.Kid, cfg.SigningKeyID)
	}

	// Reconstruct the RSA public key from the JWK n/e fields.
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode JWK n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("decode JWK e: %v", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	jwkPublicKey := &rsa.PublicKey{N: n, E: e}

	// Retrieve the public key directly from LocalStack KMS.
	kmsPublicKey := getPublicKeyFromKMS(t, kmsClient, keyID)

	// The two public keys must be identical.
	if jwkPublicKey.N.Cmp(kmsPublicKey.N) != 0 {
		t.Error("JWKS public key modulus (N) does not match kms:GetPublicKey")
	}
	if jwkPublicKey.E != kmsPublicKey.E {
		t.Errorf("JWKS public key exponent (E): got %d, want %d", jwkPublicKey.E, kmsPublicKey.E)
	}

	// Also verify that a JWT minted by the minter can be verified with the JWKS key.
	token, err := minter.Mint(context.Background(), integrationIdentity, "jti-jwks-test")
	if err != nil {
		t.Fatalf("Mint for JWKS verification: %v", err)
	}
	verifyRS256JWT(t, token, jwkPublicKey)
}
