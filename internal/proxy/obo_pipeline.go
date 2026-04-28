package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// CognitoRefresher silently refreshes a Cognito session using a stored refresh token.
type CognitoRefresher interface {
	// Refresh exchanges the given Cognito refresh token for a new TokenPair.
	// Returns ErrServiceUnavailable if the Cognito endpoint is unreachable.
	// Returns ErrUnauthorized if the refresh token has been revoked.
	Refresh(ctx context.Context, refreshToken string) (domain.TokenPair, error)
}

// OBOPipelineImpl implements the OBOPipeline interface.
// It executes the four-step OBO flow:
//
//	A. Validate Cognito token (silent refresh if expired)
//	B. OPA policy evaluation
//	C. UAT retrieval from TokenStore
//	D. Forward via RefreshTransport with Authorization: Bearer <UAT> + X-Abaris-Assertion
type OBOPipelineImpl struct {
	identity         domain.IdentityService
	policy           domain.PolicyEngine
	store            domain.TokenStore
	minter           domain.IdentityAssertionMinter
	cognitoRefresher CognitoRefresher
	transport        http.RoundTripper
	sseTransport     domain.BackendTransport // used for routes with transport: "sse"
	logger           domain.Logger
}

// compile-time check: OBOPipelineImpl satisfies the OBOPipeline interface
var _ OBOPipeline = (*OBOPipelineImpl)(nil)

// OBOPipelineConfig holds the dependencies for constructing an OBOPipelineImpl.
type OBOPipelineConfig struct {
	Identity         domain.IdentityService
	Policy           domain.PolicyEngine
	Store            domain.TokenStore
	Minter           domain.IdentityAssertionMinter
	CognitoRefresher CognitoRefresher
	Transport        http.RoundTripper
	SSETransport     domain.BackendTransport // optional; used for routes with transport: "sse"
	Logger           domain.Logger
}

// NewOBOPipeline constructs an OBOPipelineImpl from the provided config.
func NewOBOPipeline(cfg OBOPipelineConfig) (*OBOPipelineImpl, error) {
	if cfg.Identity == nil {
		return nil, fmt.Errorf("obo: IdentityService required")
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("obo: PolicyEngine required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("obo: TokenStore required")
	}
	if cfg.Minter == nil {
		return nil, fmt.Errorf("obo: IdentityAssertionMinter required")
	}
	if cfg.Transport == nil {
		return nil, fmt.Errorf("obo: Transport required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("obo: Logger required")
	}
	return &OBOPipelineImpl{
		identity:         cfg.Identity,
		policy:           cfg.Policy,
		store:            cfg.Store,
		minter:           cfg.Minter,
		cognitoRefresher: cfg.CognitoRefresher,
		transport:        cfg.Transport,
		sseTransport:     cfg.SSETransport,
		logger:           cfg.Logger,
	}, nil
}

// Execute runs the four-step OBO flow for the given tool call and route.
func (p *OBOPipelineImpl) Execute(ctx context.Context, call domain.ToolCall, route domain.RouteEntry) ([]byte, error) {
	toolName := toolNameFromCall(call)

	// Step A: Resolve Cognito identity (silent refresh if expired).
	identity, ctx, err := p.resolveIdentity(ctx)
	if err != nil {
		return nil, err
	}

	// Step B: OPA policy evaluation.
	decision, err := p.policy.Evaluate(ctx, identity, call)
	if err != nil {
		return nil, fmt.Errorf("%w: policy evaluation: %s", domain.ErrServiceUnavailable, err)
	}
	if !decision.Permitted {
		return ErrorResponse(call.ID, domain.CodePolicyDenied, "unauthorized: insufficient entitlements"), nil
	}

	// Step C: Retrieve UAT from TokenStore.
	uat, err := p.store.Get(ctx, identity.UserID, route.OBOProvider)
	if err != nil {
		if errors.Is(err, domain.ErrNotConnected) {
			msg := fmt.Sprintf("not connected: use /connect/%s to authorize", route.OBOProvider)
			return ErrorResponse(call.ID, domain.CodeUnauthenticated, msg), nil
		}
		return nil, fmt.Errorf("%w: token store get: %s", domain.ErrServiceUnavailable, err)
	}

	// Step D: Mint X-Abaris-Assertion JWT.
	bearerToken, _ := authctx.BearerTokenFromContext(ctx)
	originJTI := originJTIFromToken(bearerToken)
	assertionToken, err := p.minter.Mint(ctx, identity, originJTI)
	if err != nil {
		return nil, fmt.Errorf("%w: mint assertion token: %s", domain.ErrServiceUnavailable, err)
	}

	// Build the outbound request with UAT + X-Abaris-Assertion.
	// The caller's raw Cognito token is NOT forwarded.

	// For SSE-transport routes, delegate to the SSE backend transport which
	// handles the two-phase MCP SSE handshake (GET stream → POST message).
	if route.Transport == "sse" && p.sseTransport != nil {
		ctx = WithServiceCredential(ctx, uat.AccessToken)
		return p.sseTransport.Forward(ctx, route.BackendURI, call, assertionToken)
	}

	reqBody, err := json.Marshal(call)
	if err != nil {
		return nil, fmt.Errorf("obo: marshal call: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, route.BackendURI, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("obo: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+uat.AccessToken)
	req.Header.Set("X-Abaris-Assertion", assertionToken)

	// Attach store and provider info to context for RefreshTransport.
	ctx = withOBOContext(ctx, p.store, identity.UserID, route.OBOProvider)
	req = req.WithContext(ctx)

	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("%w: backend roundtrip: %s", domain.ErrServiceUnavailable, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("obo: read response: %w", err)
	}

	p.logger.Info("obo: tool call forwarded",
		"tool_name", toolName,
		"user_id", identity.UserID,
		"provider", route.OBOProvider,
		"status", resp.StatusCode,
	)
	return respBytes, nil
}

// resolveIdentity attempts to resolve the Cognito identity from ctx.
// If the token is expired and a CognitoRefresher is configured, it silently
// refreshes the session using the stored Cognito refresh token.
func (p *OBOPipelineImpl) resolveIdentity(ctx context.Context) (domain.IdentityContext, context.Context, error) {
	identity, err := p.identity.Resolve(ctx)
	if err == nil {
		return identity, ctx, nil
	}

	// Only attempt silent refresh for expired/unauthorized tokens.
	if !errors.Is(err, domain.ErrUnauthorized) {
		return domain.IdentityContext{}, ctx, err
	}

	if p.cognitoRefresher == nil {
		return domain.IdentityContext{}, ctx, err
	}

	// Extract userID from the (possibly expired) token for the store lookup.
	bearerToken, ok := authctx.BearerTokenFromContext(ctx)
	if !ok || bearerToken == "" {
		return domain.IdentityContext{}, ctx, err
	}

	// We need the userID to look up the Cognito refresh token.
	// Extract it from the JWT payload without signature verification.
	userID := userIDFromToken(bearerToken)
	if userID == "" {
		return domain.IdentityContext{}, ctx, fmt.Errorf("%w: cannot extract userID from expired token", domain.ErrUnauthorized)
	}

	// Retrieve stored Cognito refresh token.
	cognitoPair, storeErr := p.store.Get(ctx, userID, "cognito")
	if storeErr != nil {
		if errors.Is(storeErr, domain.ErrNotConnected) {
			return domain.IdentityContext{}, ctx, fmt.Errorf("%w: session expired: re-authentication required", domain.ErrUnauthenticated)
		}
		return domain.IdentityContext{}, ctx, fmt.Errorf("%w: retrieve cognito refresh token: %s", domain.ErrServiceUnavailable, storeErr)
	}

	// Silent refresh.
	newPair, refreshErr := p.cognitoRefresher.Refresh(ctx, cognitoPair.RefreshToken)
	if refreshErr != nil {
		return domain.IdentityContext{}, ctx, fmt.Errorf("%w: cognito silent refresh failed: %s", domain.ErrUnauthenticated, refreshErr)
	}

	// Save new pair and update context with new access token.
	if saveErr := p.store.Save(ctx, userID, "cognito", newPair); saveErr != nil {
		p.logger.Warn("obo: failed to save refreshed cognito token pair", "user_id", userID)
	}

	newCtx := authctx.WithBearerToken(ctx, newPair.AccessToken)
	identity, err = p.identity.Resolve(newCtx)
	if err != nil {
		return domain.IdentityContext{}, ctx, fmt.Errorf("%w: resolve identity after refresh: %s", domain.ErrUnauthorized, err)
	}
	return identity, newCtx, nil
}

// ---------------------------------------------------------------------------
// OBO context helpers
// ---------------------------------------------------------------------------

type oboContextKey struct{}

type oboContext struct {
	store    domain.TokenStore
	userID   string
	provider string
}

func withOBOContext(ctx context.Context, store domain.TokenStore, userID, provider string) context.Context {
	return context.WithValue(ctx, oboContextKey{}, oboContext{store: store, userID: userID, provider: provider})
}

func oboContextFromContext(ctx context.Context) (oboContext, bool) {
	v, ok := ctx.Value(oboContextKey{}).(oboContext)
	return v, ok
}

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

// userIDFromToken extracts the "sub" claim from a compact JWT without verifying the signature.
func userIDFromToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}
