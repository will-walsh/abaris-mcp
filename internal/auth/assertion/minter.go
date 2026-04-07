// Package assertion provides KMSMinter, which implements domain.IdentityAssertionMinter
// by minting short-lived RS256 JWTs signed via AWS KMS. The RSA private key never
// leaves KMS; Abaris calls kms:Sign for every token it mints.
package assertion

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// KMSClient is the subset of the AWS KMS API used by KMSMinter.
// Defined as an interface so tests can inject a mock without the real AWS SDK.
type KMSClient interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// Compile-time check: KMSMinter must implement domain.IdentityAssertionMinter (Requirement 8.1).
var _ domain.IdentityAssertionMinter = (*KMSMinter)(nil)

// KMSMinter implements domain.IdentityAssertionMinter using AWS KMS asymmetric
// signing (RSASSA_PKCS1_V1_5_SHA_256). The private key never leaves KMS.
type KMSMinter struct {
	cfg       domain.AssertionConfig
	kmsClient KMSClient
	publicKey *rsa.PublicKey // cached at startup via GetPublicKey
}

// New constructs a KMSMinter and caches the RSA public key from KMS.
// It calls kms:GetPublicKey once at startup; subsequent calls use the cached key.
// Returns an error if the KMS key is unreachable or the public key cannot be parsed.
func New(cfg domain.AssertionConfig, client KMSClient) (*KMSMinter, error) {
	if cfg.KMSKeyARN == "" {
		return nil, fmt.Errorf("assertion: KMSKeyARN is required")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("assertion: Issuer is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("assertion: Audience is required")
	}
	if cfg.TTL == 0 {
		return nil, fmt.Errorf("assertion: TTL must be non-zero")
	}

	m := &KMSMinter{cfg: cfg, kmsClient: client}
	if err := m.cachePublicKey(context.Background()); err != nil {
		return nil, fmt.Errorf("assertion: cache public key: %w", err)
	}
	return m, nil
}

// Mint produces a compact-serialized RS256 JWT signed via KMS.
//
// The JWT structure:
//
//	Header:  {"alg":"RS256","typ":"JWT","kid":"<signing_key_id>"}
//	Payload: standard OIDC top-level claims (iss, sub, aud, iat, exp, jti)
//	         + ext_identity object (origin_jti, groups, entitlements, provider)
//
// The private key never leaves KMS; only the DER-encoded signature bytes are
// returned by kms:Sign and assembled into the JWT signature segment.
//
// Implements domain.IdentityAssertionMinter.
func (m *KMSMinter) Mint(ctx context.Context, identity domain.IdentityContext, originJTI string) (string, error) {
	now := time.Now()
	exp := now.Add(m.cfg.TTL)

	// Build the ext_identity nested object (Requirement 4.6).
	extIdentity := map[string]any{
		"origin_jti":   originJTI,
		"groups":       identity.Groups,
		"entitlements": identity.Entitlements,
		"provider":     identity.Provider,
	}

	payload := map[string]any{
		"iss":          m.cfg.Issuer,
		"sub":          identity.UserID,
		"aud":          m.cfg.Audience,
		"iat":          now.Unix(),
		"exp":          exp.Unix(),
		"jti":          uuid.NewString(),
		"ext_identity": extIdentity,
	}

	headerBytes, err := json.Marshal(jwtHeader(m.cfg.SigningKeyID))
	if err != nil {
		return "", fmt.Errorf("assertion: marshal JWT header: %w", err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("assertion: marshal JWT payload: %w", err)
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerEnc + "." + payloadEnc

	// Call KMS Sign — the private key never leaves KMS.
	out, err := m.kmsClient.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(m.cfg.KMSKeyARN),
		Message:          []byte(signingInput),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return "", fmt.Errorf("%w: kms:Sign failed: %s", domain.ErrServiceUnavailable, err)
	}

	sigEnc := base64.RawURLEncoding.EncodeToString(out.Signature)
	return signingInput + "." + sigEnc, nil
}

// PublicKey returns the cached RSA public key fetched from KMS at startup.
// Used by JWKSHandler to serve GET /.well-known/jwks.json.
func (m *KMSMinter) PublicKey() *rsa.PublicKey {
	return m.publicKey
}

// JWKSHandler returns an http.HandlerFunc that serves the cached public key
// as a JSON Web Key Set (JWKS) for GET /.well-known/jwks.json.
// No per-request KMS call is made; the key is cached at startup (Requirement 4.7).
func (m *KMSMinter) JWKSHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwks := buildJWKS(m.publicKey, m.cfg.SigningKeyID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(jwks)
	}
}

// cachePublicKey calls kms:GetPublicKey once and stores the parsed *rsa.PublicKey.
func (m *KMSMinter) cachePublicKey(ctx context.Context) error {
	out, err := m.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(m.cfg.KMSKeyARN),
	})
	if err != nil {
		return fmt.Errorf("%w: kms:GetPublicKey failed: %s", domain.ErrServiceUnavailable, err)
	}

	pub, err := parseRSAPublicKey(out.PublicKey)
	if err != nil {
		return fmt.Errorf("parse RSA public key from KMS: %w", err)
	}
	m.publicKey = pub
	return nil
}

// jwtHeader builds the JWT header map for RS256 signing.
func jwtHeader(kid string) map[string]string {
	h := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	if kid != "" {
		h["kid"] = kid
	}
	return h
}

// parseRSAPublicKey parses a DER-encoded SubjectPublicKeyInfo (as returned by
// kms:GetPublicKey) into an *rsa.PublicKey.
func parseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	// Try DER directly first (kms:GetPublicKey returns DER-encoded SPKI).
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		// Fallback: try PEM-wrapped DER.
		block, _ := pem.Decode(der)
		if block == nil {
			return nil, fmt.Errorf("could not parse public key: not valid DER or PEM")
		}
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key from PEM: %w", err)
		}
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS key is not an RSA public key")
	}
	return rsaPub, nil
}
