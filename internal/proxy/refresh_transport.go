package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// TokenRefresher exchanges a stored refresh token for a new TokenPair.
type TokenRefresher interface {
	// Refresh exchanges the refresh token for a new access+refresh token pair.
	// Returns ErrServiceUnavailable if the provider is unreachable.
	// Returns ErrUnauthorized if the refresh token has been revoked.
	Refresh(ctx context.Context, userID, provider, refreshToken string) (domain.TokenPair, error)
}

// RefreshTransport wraps an http.RoundTripper and adds retry-on-401 logic.
// On HTTP 401 from the backend, it calls TokenRefresher.Refresh exactly once,
// saves the new TokenPair to the TokenStore, and retries with the new access token.
// If the refresh fails, it deletes the stale pair and returns ErrServiceUnavailable.
type RefreshTransport struct {
	inner     http.RoundTripper
	refresher TokenRefresher
	logger    domain.Logger
}

// compile-time check
var _ http.RoundTripper = (*RefreshTransport)(nil)

func NewRefreshTransport(inner http.RoundTripper, refresher TokenRefresher, logger domain.Logger) *RefreshTransport {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &RefreshTransport{inner: inner, refresher: refresher, logger: logger}
}

func (t *RefreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request body so we can replay it on retry.
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("refresh_transport: read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Only retry on 401.
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	resp.Body.Close()

	// Extract OBO context (store, userID, provider) from request context.
	oboCtx, ok := oboContextFromContext(req.Context())
	if !ok || t.refresher == nil {
		// No OBO context or no refresher — return the 401 as-is.
		return resp, nil
	}

	t.logger.Info("refresh_transport: 401 received, attempting token refresh",
		"user_id", oboCtx.userID, "provider", oboCtx.provider)

	// Retrieve current refresh token.
	currentPair, err := oboCtx.store.Get(req.Context(), oboCtx.userID, oboCtx.provider)
	if err != nil {
		return nil, fmt.Errorf("%w: retrieve token for refresh: %s", domain.ErrServiceUnavailable, err)
	}

	// Refresh exactly once.
	newPair, err := t.refresher.Refresh(req.Context(), oboCtx.userID, oboCtx.provider, currentPair.RefreshToken)
	if err != nil {
		// Delete stale pair on refresh failure.
		_ = oboCtx.store.Delete(req.Context(), oboCtx.userID, oboCtx.provider)
		t.logger.Error("refresh_transport: token refresh failed, deleted stale pair",
			"user_id", oboCtx.userID, "provider", oboCtx.provider)
		return nil, fmt.Errorf("%w: downstream token refresh failed: %s", domain.ErrServiceUnavailable, err)
	}

	// Save new pair.
	if err := oboCtx.store.Save(req.Context(), oboCtx.userID, oboCtx.provider, newPair); err != nil {
		t.logger.Warn("refresh_transport: failed to save new token pair",
			"user_id", oboCtx.userID, "provider", oboCtx.provider)
	}

	// Retry with new access token.
	retryReq := req.Clone(req.Context())
	retryReq.Header.Set("Authorization", "Bearer "+newPair.AccessToken)
	if bodyBytes != nil {
		retryReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		retryReq.ContentLength = int64(len(bodyBytes))
	}

	t.logger.Info("refresh_transport: retrying with new access token",
		"user_id", oboCtx.userID, "provider", oboCtx.provider)
	return t.inner.RoundTrip(retryReq)
}

// ---------------------------------------------------------------------------
// OAuth2TokenRefresher (task 12.8)
// ---------------------------------------------------------------------------

// OAuth2TokenRefresher implements TokenRefresher using golang.org/x/oauth2.
// It exchanges the stored refresh token with the Secondary_Provider token endpoint.
type OAuth2TokenRefresher struct {
	providers map[string]domain.SecondaryProviderConfig // keyed by provider name
	logger    domain.Logger
}

// compile-time check
var _ TokenRefresher = (*OAuth2TokenRefresher)(nil)

func NewOAuth2TokenRefresher(providers []domain.SecondaryProviderConfig, logger domain.Logger) *OAuth2TokenRefresher {
	m := make(map[string]domain.SecondaryProviderConfig, len(providers))
	for _, p := range providers {
		m[p.Name] = p
	}
	return &OAuth2TokenRefresher{providers: m, logger: logger}
}

func (r *OAuth2TokenRefresher) Refresh(ctx context.Context, userID, provider, refreshToken string) (domain.TokenPair, error) {
	cfg, ok := r.providers[provider]
	if !ok {
		return domain.TokenPair{}, fmt.Errorf("%w: unknown provider %q", domain.ErrServiceUnavailable, provider)
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL: cfg.TokenURL,
		},
	}

	// Use the stored refresh token to get a new token.
	token := &oauth2.Token{RefreshToken: refreshToken}
	tokenSource := oauthCfg.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		r.logger.Error("oauth2_refresher: token refresh failed",
			"user_id", userID, "provider", provider)
		return domain.TokenPair{}, fmt.Errorf("%w: oauth2 refresh for provider %q: %s", domain.ErrServiceUnavailable, provider, err)
	}

	return domain.TokenPair{
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
	}, nil
}
