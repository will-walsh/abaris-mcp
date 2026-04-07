// Package authctx defines shared context keys for credential propagation
// between the transport layer and the identity adapters.
// It is a leaf package with no internal imports to avoid import cycles.
package authctx

import "context"

type contextKey int

const (
	bearerTokenKey      contextKey = iota
	samlAssertionCtxKey contextKey = iota
)

// WithBearerToken returns a new context carrying the given OIDC Bearer token.
// The transport layer calls this before invoking IdentityService.Resolve.
func WithBearerToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, bearerTokenKey, token)
}

// BearerTokenFromContext retrieves the Bearer token stored by WithBearerToken.
func BearerTokenFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(bearerTokenKey).(string)
	return v, ok
}

// WithSAMLAssertion returns a new context carrying the raw SAML assertion XML.
// The transport layer calls this before invoking IdentityService.Resolve.
func WithSAMLAssertion(ctx context.Context, assertionXML string) context.Context {
	return context.WithValue(ctx, samlAssertionCtxKey, assertionXML)
}

// SAMLAssertionFromContext retrieves the SAML assertion stored by WithSAMLAssertion.
func SAMLAssertionFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(samlAssertionCtxKey).(string)
	return v, ok
}
