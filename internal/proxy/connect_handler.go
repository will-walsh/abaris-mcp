package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// ConnectHandler handles the OAuth2 authorization code flow for onboarding users
// to secondary providers (e.g. GitHub OAuth App).
//
// GET /connect/{provider}          — validate Cognito token → mint state → redirect to auth URL
// GET /connect/{provider}/callback — verify state → exchange code → save TokenPair
type ConnectHandler struct {
	identity    domain.IdentityService
	store       domain.TokenStore
	providers   map[string]domain.SecondaryProviderConfig // keyed by provider name
	stateKey    []byte                                    // HMAC-SHA256 key for state tokens
	stateTTL    time.Duration                             // default 10 minutes
	redirectURI string                                    // base URL for callback redirect_uri
	logger      domain.Logger
}

// ConnectHandlerConfig holds the dependencies for constructing a ConnectHandler.
type ConnectHandlerConfig struct {
	Identity    domain.IdentityService
	Store       domain.TokenStore
	Providers   []domain.SecondaryProviderConfig
	StateKey    []byte        // HMAC-SHA256 key from Secrets Manager
	StateTTL    time.Duration // defaults to 10 minutes if zero
	RedirectURI string        // base URL for /connect/{provider}/callback
	Logger      domain.Logger
}

// NewConnectHandler constructs a ConnectHandler from the provided config.
func NewConnectHandler(cfg ConnectHandlerConfig) (*ConnectHandler, error) {
	if cfg.Identity == nil {
		return nil, fmt.Errorf("connect: IdentityService required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("connect: TokenStore required")
	}
	if len(cfg.StateKey) == 0 {
		return nil, fmt.Errorf("connect: StateKey required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("connect: Logger required")
	}
	ttl := cfg.StateTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	m := make(map[string]domain.SecondaryProviderConfig, len(cfg.Providers))
	for _, p := range cfg.Providers {
		m[p.Name] = p
	}
	return &ConnectHandler{
		identity:    cfg.Identity,
		store:       cfg.Store,
		providers:   m,
		stateKey:    cfg.StateKey,
		stateTTL:    ttl,
		redirectURI: cfg.RedirectURI,
		logger:      cfg.Logger,
	}, nil
}

// statePayload is the data encoded in the HMAC-signed state token.
type statePayload struct {
	UserID    string    `json:"user_id"`
	Provider  string    `json:"provider"`
	ExpiresAt time.Time `json:"expires_at"`
}

// mintState creates a base64url-encoded HMAC-SHA256 signed state token.
// Format: base64url(json(payload)) + "." + base64url(hmac)
func mintState(key []byte, userID, provider string, ttl time.Duration) (string, error) {
	payload := statePayload{
		UserID:    userID,
		Provider:  provider,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("mint state: marshal: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(encodedPayload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encodedPayload + "." + sig, nil
}

// verifyState verifies the HMAC signature and expiry of a state token.
// Returns the decoded statePayload on success.
func verifyState(key []byte, state string) (statePayload, error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return statePayload{}, fmt.Errorf("invalid state format")
	}
	encodedPayload, sig := parts[0], parts[1]

	// Verify HMAC.
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(encodedPayload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return statePayload{}, fmt.Errorf("invalid state signature")
	}

	// Decode payload.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return statePayload{}, fmt.Errorf("decode state payload: %w", err)
	}
	var payload statePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return statePayload{}, fmt.Errorf("unmarshal state payload: %w", err)
	}

	// Check expiry.
	if time.Now().UTC().After(payload.ExpiresAt) {
		return statePayload{}, fmt.Errorf("state expired: restart the connect flow")
	}
	return payload, nil
}

// ServeConnect handles GET /connect/{provider}.
// Validates the Cognito Bearer token, mints a state token, and redirects to the OAuth2 auth URL.
func (h *ConnectHandler) ServeConnect(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	cfg, ok := h.providers[providerName]
	if !ok {
		http.Error(w, `{"error":"unknown provider"}`, http.StatusNotFound)
		return
	}

	// Inject credentials from HTTP request into context before resolving identity.
	ctx := injectCredentialsFromHTTP(r.Context(), r)

	// Validate Cognito Bearer token.
	identity, err := h.identity.Resolve(ctx)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Mint state token.
	state, err := mintState(h.stateKey, identity.UserID, providerName, h.stateTTL)
	if err != nil {
		h.logger.Error("connect: mint state failed", "user_id", identity.UserID, "provider", providerName)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Build OAuth2 auth URL.
	oauthCfg := &oauth2.Config{
		ClientID:    cfg.ClientID,
		Scopes:      cfg.Scopes,
		RedirectURL: h.redirectURI + "/connect/" + providerName + "/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
	}
	authURL := oauthCfg.AuthCodeURL(state)

	h.logger.Info("connect: redirecting to auth URL", "user_id", identity.UserID, "provider", providerName)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ServeCallback handles GET /connect/{provider}/callback.
// Verifies state, exchanges code for tokens, saves encrypted TokenPair.
func (h *ConnectHandler) ServeCallback(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if _, ok := h.providers[providerName]; !ok {
		http.Error(w, `{"error":"unknown provider"}`, http.StatusNotFound)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// Verify state.
	payload, err := verifyState(h.stateKey, state)
	if err != nil {
		h.logger.Info("connect: invalid state", "provider", providerName, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":%q}`, err.Error())
		return
	}

	if payload.Provider != providerName {
		http.Error(w, `{"error":"state provider mismatch"}`, http.StatusBadRequest)
		return
	}

	cfg := h.providers[providerName]
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		RedirectURL:  h.redirectURI + "/connect/" + providerName + "/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
	}

	// Exchange code for token.
	token, err := oauthCfg.Exchange(r.Context(), code)
	if err != nil {
		h.logger.Error("connect: code exchange failed", "provider", providerName, "user_id", payload.UserID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"error":"code exchange failed","provider":%q}`, providerName)
		return
	}

	// Save encrypted TokenPair.
	pair := domain.TokenPair{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}
	if err := h.store.Save(r.Context(), payload.UserID, providerName, pair); err != nil {
		h.logger.Error("connect: save token pair failed", "provider", providerName, "user_id", payload.UserID)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	h.logger.Info("connect: token pair saved", "user_id", payload.UserID, "provider", providerName)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"connected","provider":%q}`, providerName)
}
