// Package auth provides the MultiProviderIdentityService that dispatches
// inbound credentials to the correct OIDC or SAML adapter based on the
// credential type and issuer present in the request context.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/auth/oidc"
	"github.com/will-walsh/abaris-mcp/internal/auth/saml"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// Compile-time interface satisfaction checks (Requirement 8.3).
var _ domain.IdentityService = (*oidc.OIDCAdapter)(nil)
var _ domain.IdentityService = (*saml.SAMLAdapter)(nil)
var _ domain.IdentityService = (*MultiProviderIdentityService)(nil)

// MultiProviderIdentityService dispatches to the correct IdentityService adapter
// based on the credential type and issuer present in the request context.
//
// Dispatch logic:
//  1. If a SAML assertion is present in ctx (set via authctx.WithSAMLAssertion),
//     the assertion's Issuer element is extracted and matched against the
//     registered SAML adapters (keyed by IdP entity ID / issuer).
//  2. If a Bearer token is present in ctx (set via authctx.WithBearerToken),
//     the token's "iss" claim is extracted (without full verification) and
//     matched against the registered OIDC adapters (keyed by issuer URL).
//  3. If neither credential is present, ErrUnauthenticated is returned.
type MultiProviderIdentityService struct {
	// oidcAdapters maps OIDC issuer URL → OIDCAdapter.
	oidcAdapters map[string]*oidc.OIDCAdapter
	// samlAdapters maps SAML IdP entity ID (issuer) → SAMLAdapter.
	samlAdapters map[string]*saml.SAMLAdapter
	logger       domain.Logger
}

// NewMultiProviderIdentityService constructs a MultiProviderIdentityService.
// oidcAdapters is keyed by the OIDC issuer URL (must match the "iss" claim).
// samlAdapters is keyed by the IdP entity ID (must match the Issuer element).
func NewMultiProviderIdentityService(
	oidcAdapters map[string]*oidc.OIDCAdapter,
	samlAdapters map[string]*saml.SAMLAdapter,
	logger domain.Logger,
) (*MultiProviderIdentityService, error) {
	if len(oidcAdapters)+len(samlAdapters) == 0 {
		return nil, fmt.Errorf("auth: at least one identity provider adapter is required")
	}
	return &MultiProviderIdentityService{
		oidcAdapters: oidcAdapters,
		samlAdapters: samlAdapters,
		logger:       logger,
	}, nil
}

// Resolve dispatches to the correct adapter based on the credential in ctx.
// It returns ErrUnauthenticated if no credential is present, or ErrUnauthorized
// if no registered adapter matches the credential's issuer.
func (m *MultiProviderIdentityService) Resolve(ctx context.Context) (domain.IdentityContext, error) {
	// 1. Try SAML assertion first.
	if assertionXML, ok := authctx.SAMLAssertionFromContext(ctx); ok && strings.TrimSpace(assertionXML) != "" {
		issuer, err := samlIssuerFromXML(assertionXML)
		if err != nil {
			m.logger.Debug("auth: could not extract SAML issuer", "error", err)
			return domain.IdentityContext{}, fmt.Errorf("%w: could not extract SAML issuer", domain.ErrUnauthorized)
		}
		adapter, found := m.samlAdapters[issuer]
		if !found {
			m.logger.Warn("auth: no SAML adapter registered for issuer", "issuer", issuer)
			return domain.IdentityContext{}, fmt.Errorf("%w: no SAML provider registered for issuer %q", domain.ErrUnauthorized, issuer)
		}
		return adapter.Resolve(ctx)
	}

	// 2. Try Bearer token (OIDC).
	if token, ok := authctx.BearerTokenFromContext(ctx); ok && strings.TrimSpace(token) != "" {
		issuer, err := jwtIssuerFromToken(token)
		if err == nil {
			adapter, found := m.oidcAdapters[issuer]
			if !found {
				m.logger.Warn("auth: no OIDC adapter registered for issuer", "issuer", issuer)
				return domain.IdentityContext{}, fmt.Errorf("%w: no OIDC provider registered for issuer %q", domain.ErrUnauthorized, issuer)
			}
			return adapter.Resolve(ctx)
		}

		// If issuer extraction failed but there is exactly one OIDC adapter,
		// delegate to it directly (single-provider shortcut).
		m.logger.Debug("auth: could not extract JWT issuer, trying single-provider shortcut", "error", err)
		if len(m.oidcAdapters) == 1 {
			for _, adapter := range m.oidcAdapters {
				return adapter.Resolve(ctx)
			}
		}

		return domain.IdentityContext{}, fmt.Errorf("%w: could not determine OIDC provider from token", domain.ErrUnauthorized)
	}

	return domain.IdentityContext{}, domain.ErrUnauthenticated
}

// jwtIssuerFromToken extracts the "iss" claim from a JWT without verifying the
// signature. This is safe here because we only use the issuer to select the
// correct adapter; the adapter itself performs full signature verification.
func jwtIssuerFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a valid JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal JWT payload: %w", err)
	}
	if claims.Issuer == "" {
		return "", fmt.Errorf("JWT payload has no 'iss' claim")
	}
	return claims.Issuer, nil
}

// samlIssuerFromXML extracts the Issuer element from a SAML assertion XML string
// with a minimal string search to avoid a full XML parse.
func samlIssuerFromXML(assertionXML string) (string, error) {
	// Try plain <Issuer>...</Issuer> first.
	const open = "<Issuer>"
	const close = "</Issuer>"
	if start := strings.Index(assertionXML, open); start != -1 {
		if end := strings.Index(assertionXML[start:], close); end != -1 {
			return strings.TrimSpace(assertionXML[start+len(open) : start+end]), nil
		}
	}
	// Try namespace-qualified form, e.g. <saml:Issuer>...</saml:Issuer>.
	if start := strings.Index(assertionXML, ":Issuer>"); start != -1 {
		if end := strings.Index(assertionXML[start:], "</"); end != -1 {
			return strings.TrimSpace(assertionXML[start+len(":Issuer>") : start+end]), nil
		}
	}
	return "", fmt.Errorf("no Issuer element found in SAML assertion")
}
