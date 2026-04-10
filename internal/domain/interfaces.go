package domain

import "context"

// IdentityService resolves a caller's identity from an inbound request context.
// Implementations must not expose OIDC or SAML library types in their signatures.
type IdentityService interface {
	// Resolve extracts the caller's credential from ctx and returns a normalized
	// IdentityContext. Returns ErrUnauthenticated, ErrUnauthorized, or
	// ErrServiceUnavailable on failure.
	Resolve(ctx context.Context) (IdentityContext, error)
}

// PolicyEngine evaluates whether a ToolCall is permitted for a given identity.
// The interface is independent of OPA so alternative evaluators can be substituted.
type PolicyEngine interface {
	// Evaluate returns a PolicyDecision with a permit/deny outcome and the
	// identifier of the matched rule.
	Evaluate(ctx context.Context, identity IdentityContext, call ToolCall) (PolicyDecision, error)

	// FilterTools returns the subset of toolNames that the given identity is
	// permitted to invoke under the active policy. Used for Discovery (list_tools).
	FilterTools(ctx context.Context, identity IdentityContext, toolNames []string) ([]string, error)
}

// BackendTransport forwards a permitted ToolCall to the appropriate backend MCP
// server using Abaris's own service credentials and the signed Identity Assertion
// Token. The caller's raw credential is never forwarded.
type BackendTransport interface {
	// Forward sends the tool call to backendURL, attaching service credentials
	// and the X-Abaris-Identity header. Returns the unmodified response bytes.
	Forward(ctx context.Context, backendURL string, call ToolCall, identityToken string) ([]byte, error)
}

// IdentityAssertionMinter mints short-lived signed JWTs for backend attribution.
// The production implementation calls AWS KMS Sign; the private key never leaves KMS.
// Implementations must not expose AWS SDK types in their signatures.
type IdentityAssertionMinter interface {
	// Mint produces a signed Identity Assertion Token for the given IdentityContext.
	// originJTI is the "jti" claim of the inbound Cognito token; it is embedded in
	// the ext_identity.origin_jti field of the minted JWT for full request traceability.
	// Returns a compact-serialized JWT for use in the X-Abaris-Identity header.
	// Returns ErrServiceUnavailable if signing fails.
	Mint(ctx context.Context, identity IdentityContext, originJTI string) (string, error)
}

// Logger is the structured logging interface used throughout Abaris.
// The production implementation uses Go's slog package with JSON output.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
}

// TokenStore persists encrypted Token_Pairs per user per provider.
// The primary key is the Cognito sub claim (IdentityContext.UserID).
// Implementations must encrypt token values at rest using KMS envelope encryption.
type TokenStore interface {
	// Get retrieves and decrypts the TokenPair for the given user and provider.
	// Returns ErrNotConnected if no pair exists for this user+provider combination.
	Get(ctx context.Context, userID, provider string) (TokenPair, error)

	// Save encrypts and persists the TokenPair for the given user and provider.
	Save(ctx context.Context, userID, provider string, pair TokenPair) error

	// Delete removes the TokenPair for the given user and provider.
	// Returns nil if the pair does not exist (idempotent).
	Delete(ctx context.Context, userID, provider string) error
}
