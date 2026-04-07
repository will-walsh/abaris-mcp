// Package oidc provides an OIDCAdapter that implements domain.IdentityService
// by validating Bearer tokens using the zitadel/oidc library and normalizing
// the resulting claims into a domain.IdentityContext.
package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	zoidc "github.com/zitadel/oidc/v3/pkg/oidc"
)

// OIDCAdapter implements domain.IdentityService for OIDC Bearer token validation.
type OIDCAdapter struct {
	providerName string
	verifier     *rp.IDTokenVerifier
	groupsClaim  string // JWT claim name for groups; defaults to "groups"
	cache        *ttlcache.Cache[string, domain.IdentityContext]
	logger       domain.Logger
}

// Config holds the parameters needed to construct an OIDCAdapter.
type Config struct {
	ProviderName string
	Issuer       string
	JWKSURL      string
	ClientID     string
	Audience     string
	// GroupsClaim is the JWT claim name that contains the user's groups.
	// Defaults to "groups" if empty.
	GroupsClaim string
	// CacheTTL is how long a resolved IdentityContext is cached.
	// Defaults to 5 minutes if zero.
	CacheTTL time.Duration
}

// New constructs an OIDCAdapter from the given Config.
// It creates a remote key set from the JWKS URL and builds an IDTokenVerifier.
func New(cfg Config, logger domain.Logger) (*OIDCAdapter, error) {
	if cfg.ProviderName == "" {
		return nil, fmt.Errorf("oidc: provider name is required")
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("oidc: JWKS URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: client ID is required")
	}

	keySet := rp.NewRemoteKeySet(http.DefaultClient, cfg.JWKSURL)

	opts := []rp.VerifierOption{
		rp.WithIssuedAtOffset(5 * time.Second),
	}

	// Use Audience as the expected audience if provided; otherwise fall back to ClientID.
	// NewIDTokenVerifier uses the second argument as the expected audience claim.
	audience := cfg.ClientID
	if cfg.Audience != "" {
		audience = cfg.Audience
	}

	verifier := rp.NewIDTokenVerifier(cfg.Issuer, audience, keySet, opts...)

	groupsClaim := cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	cache := ttlcache.New[string, domain.IdentityContext](
		ttlcache.WithTTL[string, domain.IdentityContext](cacheTTL),
	)
	go cache.Start()

	return &OIDCAdapter{
		providerName: cfg.ProviderName,
		verifier:     verifier,
		groupsClaim:  groupsClaim,
		cache:        cache,
		logger:       logger,
	}, nil
}

// Resolve extracts the Bearer token from ctx, validates it using zitadel/oidc,
// and normalizes the claims into a domain.IdentityContext.
// Returns domain.ErrUnauthenticated if no token is present,
// domain.ErrUnauthorized if the token is invalid or expired,
// and domain.ErrServiceUnavailable if the JWKS endpoint is unreachable.
func (a *OIDCAdapter) Resolve(ctx context.Context) (domain.IdentityContext, error) {
	token, ok := authctx.BearerTokenFromContext(ctx)
	if !ok || strings.TrimSpace(token) == "" {
		return domain.IdentityContext{}, domain.ErrUnauthenticated
	}

	// Check cache first to avoid repeated JWKS round-trips.
	if item := a.cache.Get(token); item != nil {
		return item.Value(), nil
	}

	claims, err := rp.VerifyIDToken[*zoidc.IDTokenClaims](ctx, token, a.verifier)
	if err != nil {
		// Distinguish network/JWKS errors from token validation errors.
		if isServiceUnavailable(err) {
			return domain.IdentityContext{}, fmt.Errorf("%w: %s", domain.ErrServiceUnavailable, err)
		}
		return domain.IdentityContext{}, fmt.Errorf("%w: %s", domain.ErrUnauthorized, err)
	}

	identity := a.normalizeClaims(claims)
	a.cache.Set(token, identity, ttlcache.DefaultTTL)

	a.logger.Debug("oidc: resolved identity",
		"provider", a.providerName,
		"user_id", identity.UserID,
		"groups", identity.Groups,
	)

	return identity, nil
}

// Stop shuts down the background cache eviction goroutine.
func (a *OIDCAdapter) Stop() {
	a.cache.Stop()
}

// normalizeClaims converts zitadel IDTokenClaims into a domain.IdentityContext.
func (a *OIDCAdapter) normalizeClaims(claims *zoidc.IDTokenClaims) domain.IdentityContext {
	identity := domain.IdentityContext{
		UserID:   claims.Subject,
		Email:    claims.UserInfoEmail.Email,
		Provider: a.providerName,
	}

	// Extract groups from the configured claim name.
	if raw, ok := claims.Claims[a.groupsClaim]; ok {
		identity.Groups = toStringSlice(raw)
	}

	// Extract entitlements from the "entitlements" claim if present.
	if raw, ok := claims.Claims["entitlements"]; ok {
		identity.Entitlements = toStringSlice(raw)
	}

	return identity
}

// bearerTokenFromContext retrieves the Bearer token stored by authctx.WithBearerToken.
func bearerTokenFromContext(ctx context.Context) (string, bool) {
	return authctx.BearerTokenFromContext(ctx)
}

// isServiceUnavailable heuristically identifies network-level errors that
// indicate the JWKS endpoint is unreachable rather than a token validation failure.
func isServiceUnavailable(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "i/o timeout")
}

// toStringSlice converts an interface{} value (from JWT extra claims) to []string.
// Handles []interface{} (JSON arrays) and plain string values.
func toStringSlice(v any) []string {
	switch val := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	case string:
		if val == "" {
			return nil
		}
		return []string{val}
	default:
		return nil
	}
}
