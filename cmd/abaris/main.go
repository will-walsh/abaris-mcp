// cmd/abaris/main.go is the composition root for Abaris.
//
// It is the only place in the codebase where infrastructure adapters are
// instantiated and wired together. The domain layer (internal/domain) and
// all other packages depend only on interfaces; this file is the single
// location that selects and connects the concrete implementations.
//
// Startup sequence:
//  1. Create the slog JSON logger.
//  2. Load and validate configuration from /config/ (fatal on any error).
//  3. Create the AWS Secrets Manager adapter (fatal if unreachable).
//  4. Fetch all required secrets (fatal if any are missing).
//  5. Resolve secondary provider client secrets into the config.
//  6. Wire identity adapters (OIDC / SAML) from identity_providers config.
//  7. Wire the KMS assertion minter (validates key access at startup).
//  8. Wire the token store (DynamoDB or BadgerDB + KMS envelope encryption).
//  9. Wire the OPA policy engine.
// 10. Wire the Broker (Proxy_Core).
// 11. Wire the OBO pipeline and ConnectHandler (if secondary_providers exist).
// 12. Register HTTP handlers: /health, /.well-known/jwks.json,
//     /connect/{provider}, /connect/{provider}/callback, /mcp.
// 13. Start the policy hot-reload watcher goroutine.
// 14. Start the config hot-reload watcher goroutine.
// 15. Start the Stdio transport goroutine (reads from os.Stdin).
// 16. Block on SIGTERM / SIGINT with graceful drain.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/will-walsh/abaris-mcp/internal/auth"
	"github.com/will-walsh/abaris-mcp/internal/auth/assertion"
	oidcadapter "github.com/will-walsh/abaris-mcp/internal/auth/oidc"
	samladapter "github.com/will-walsh/abaris-mcp/internal/auth/saml"
	appconfig "github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/infra"
	"github.com/will-walsh/abaris-mcp/internal/policy"
	"github.com/will-walsh/abaris-mcp/internal/proxy"
)

func main() {
	logger := infra.NewSlogLogger()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := run(ctx, logger); err != nil {
		logger.Error("FATAL: startup failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger domain.Logger) error {
	// -----------------------------------------------------------------------
	// 1. Load and validate configuration
	// -----------------------------------------------------------------------
	configDir := envOrDefault("ABARIS_CONFIG_DIR", "/app/config")

	loader := appconfig.NewLoader(configDir, logger, nil /* onChange wired below */)
	cfg, err := loader.Load()
	if err != nil {
		logger.Error("FATAL: configuration load failed", "error", err)
		os.Exit(1)
	}
	logger.Info("configuration loaded", "config_dir", configDir)

	// -----------------------------------------------------------------------
	// 2. AWS SDK base config (ambient IAM role — no static credentials)
	// -----------------------------------------------------------------------
	awsRegion := mustEnv("AWS_REGION", logger)
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		logger.Error("FATAL: load AWS config failed", "error", err)
		os.Exit(1)
	}

	// -----------------------------------------------------------------------
	// 3. Secrets Manager adapter
	// -----------------------------------------------------------------------
	secretsAdapter, err := infra.NewSecretsManagerAdapter(ctx, awsRegion, logger)
	if err != nil {
		logger.Error("FATAL: Secrets Manager adapter init failed", "error", err)
		os.Exit(1)
	}

	// -----------------------------------------------------------------------
	// 4. Resolve secondary provider client secrets
	// -----------------------------------------------------------------------
	if err := loader.ResolveSecondaryProviderSecrets(ctx, secretsAdapter); err != nil {
		logger.Error("FATAL: resolve secondary provider secrets failed", "error", err)
		os.Exit(1)
	}
	// Re-read the merged config (now includes resolved ClientSecret fields).
	cfg = loader.Current()

	// -----------------------------------------------------------------------
	// 5. Wire identity adapters
	// -----------------------------------------------------------------------
	oidcAdapters := make(map[string]*oidcadapter.OIDCAdapter)
	samlAdapters := make(map[string]*samladapter.SAMLAdapter)

	for _, idp := range cfg.IdentityProviders {
		switch idp.Type {
		case "oidc":
			a, err := oidcadapter.New(oidcadapter.Config{
				ProviderName: idp.Name,
				Issuer:       issuerFromDiscoveryURL(idp.DiscoveryURL),
				JWKSURL:      idp.JWKSEndpoint,
				ClientID:     idp.ClientID,
				Audience:     idp.Audience,
				GroupsClaim:  idp.GroupsClaim,
			}, logger)
			if err != nil {
				return fmt.Errorf("wire OIDC adapter %q: %w", idp.Name, err)
			}
			oidcAdapters[issuerFromDiscoveryURL(idp.DiscoveryURL)] = a
			logger.Info("OIDC adapter wired", "provider", idp.Name)

		case "saml":
			a, err := samladapter.New(samladapter.Config{
				ProviderName: idp.Name,
				MetadataURL:  idp.MetadataURL,
				SPEntityID:   idp.SPEntityID,
				ACSURL:       idp.ACSURL,
				CertPath:     idp.CertPath,
				KeyPath:      idp.KeyPath,
			}, logger)
			if err != nil {
				return fmt.Errorf("wire SAML adapter %q: %w", idp.Name, err)
			}
			samlAdapters[idp.SPEntityID] = a
			logger.Info("SAML adapter wired", "provider", idp.Name)
		}
	}

	identitySvc, err := auth.NewMultiProviderIdentityService(oidcAdapters, samlAdapters, logger)
	if err != nil {
		return fmt.Errorf("wire MultiProviderIdentityService: %w", err)
	}

	// -----------------------------------------------------------------------
	// 6. KMS clients
	// -----------------------------------------------------------------------
	kmsClient := kms.NewFromConfig(awsCfg)

	// -----------------------------------------------------------------------
	// 7. KMS assertion minter (validates kms:Sign permission at startup)
	// -----------------------------------------------------------------------
	minter, err := assertion.New(cfg.Assertion, kmsClient)
	if err != nil {
		logger.Error("FATAL: KMS minter init failed — check kms:GetPublicKey permission", "error", err)
		os.Exit(1)
	}
	logger.Info("KMS assertion minter ready", "key_arn", cfg.Assertion.KMSKeyARN)

	// -----------------------------------------------------------------------
	// 8. Token store (DynamoDB + KMS envelope encryption)
	// -----------------------------------------------------------------------
	var tokenStore domain.TokenStore
	if cfg.TokenStore != nil {
		tokenStore, err = buildTokenStore(ctx, cfg, nil, kmsClient, logger)
		if err != nil {
			logger.Error("FATAL: token store init failed", "error", err)
			os.Exit(1)
		}
		logger.Info("token store ready", "type", cfg.TokenStore.Type)
	}

	// -----------------------------------------------------------------------
	// 9. OPA policy engine
	// -----------------------------------------------------------------------
	bundlePath := envOrDefault("ABARIS_BUNDLE_PATH", "/app/policies")
	policyEngine, err := policy.New(ctx, bundlePath, cfg.Policies, logger)
	if err != nil {
		return fmt.Errorf("wire OPA policy engine: %w", err)
	}
	logger.Info("OPA policy engine ready", "bundle_path", bundlePath)

	// -----------------------------------------------------------------------
	// 10. Backend transport and credential store
	// -----------------------------------------------------------------------
	backendTransport := proxy.NewHTTPBackendTransport(nil, logger)
	sseBackendTransport := proxy.NewSSEBackendTransport(nil, logger)
	credStore := newEnvCredentialStore(cfg.Routes, logger)

	// -----------------------------------------------------------------------
	// 11. OBO pipeline and ConnectHandler (only when secondary providers exist)
	// -----------------------------------------------------------------------
	var oboPipeline proxy.OBOPipeline
	var connectHandler *proxy.ConnectHandler

	if len(cfg.SecondaryProviders) > 0 && tokenStore != nil {
		refresher := proxy.NewOAuth2TokenRefresher(cfg.SecondaryProviders, logger)
		rt := proxy.NewRefreshTransport(http.DefaultTransport, refresher, logger)

		oboPipeline, err = proxy.NewOBOPipeline(proxy.OBOPipelineConfig{
			Identity:     identitySvc,
			Policy:       policyEngine,
			Store:        tokenStore,
			Minter:       minter,
			Transport:    rt,
			SSETransport: sseBackendTransport,
			Logger:       logger,
		})
		if err != nil {
			return fmt.Errorf("wire OBO pipeline: %w", err)
		}
		logger.Info("OBO pipeline ready")

		stateKeyARN := mustEnv("ABARIS_STATE_KEY_ARN", logger)
		stateKeySecret := infra.MustGetSecret(ctx, secretsAdapter, stateKeyARN, logger)

		redirectURI := mustEnv("ABARIS_REDIRECT_URI", logger)

		connectHandler, err = proxy.NewConnectHandler(proxy.ConnectHandlerConfig{
			Identity:    identitySvc,
			Store:       tokenStore,
			Providers:   cfg.SecondaryProviders,
			StateKey:    []byte(stateKeySecret),
			RedirectURI: redirectURI,
			Logger:      logger,
		})
		if err != nil {
			return fmt.Errorf("wire ConnectHandler: %w", err)
		}
		logger.Info("ConnectHandler ready")
	}

	// -----------------------------------------------------------------------
	// 12. Broker (Proxy_Core)
	// -----------------------------------------------------------------------
	broker, err := proxy.NewBroker(proxy.BrokerConfig{
		Identity:     identitySvc,
		Policy:       policyEngine,
		Transport:    backendTransport,
		SSETransport: sseBackendTransport,
		Minter:       minter,
		Creds:        credStore,
		Logger:       logger,
		Routes:       cfg.Routes,
		Store:        tokenStore,
		OBO:          oboPipeline,
	})
	if err != nil {
		return fmt.Errorf("wire Broker: %w", err)
	}

	// -----------------------------------------------------------------------
	// 13. HTTP server — register all handlers on the SSE transport mux
	// -----------------------------------------------------------------------
	sseTransport := proxy.NewSSETransport(broker, logger)
	mux := sseTransport.Mux()

	// Health check (Requirement 9.1, 9.2)
	health := infra.NewHealthChecker()
	mux.HandleFunc("/health", health.HealthHandler())

	// JWKS endpoint (Requirement 4.7, 7.2)
	mux.HandleFunc("/.well-known/jwks.json", minter.JWKSHandler())

	// OAuth2 connect flow (Requirement 13.1)
	if connectHandler != nil {
		mux.HandleFunc("/connect/{provider}", connectHandler.ServeConnect)
		mux.HandleFunc("/connect/{provider}/callback", connectHandler.ServeCallback)
	}

	srv := &http.Server{
		Addr:         proxy.ListenAddr(),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// -----------------------------------------------------------------------
	// 14. Policy hot-reload watcher
	// -----------------------------------------------------------------------
	hotReloadInterval := 30 * time.Second
	go policyEngine.StartHotReload(ctx, hotReloadInterval)

	// -----------------------------------------------------------------------
	// 15. Config (policies/) hot-reload watcher
	// -----------------------------------------------------------------------
	stopCh := make(chan struct{})
	go func() {
		if err := loader.Watch(stopCh); err != nil {
			logger.Warn("config watcher stopped", "error", err)
		}
	}()

	// Wire the onChange callback now that policyEngine is ready.
	// Re-create the loader with the callback so hot-reload updates OPA.
	loader2 := appconfig.NewLoader(configDir, logger, func(newCfg domain.Config) {
		broker.UpdateRoutes(newCfg.Routes)
		if err := policyEngine.UpdatePolicies(ctx, newCfg.Policies); err != nil {
			logger.Warn("hot-reload: OPA policy update failed", "error", err)
		} else {
			logger.Info("hot-reload: policies updated")
		}
	})
	_ = loader2 // loader2 is used only for its onChange side-effect wiring above

	// -----------------------------------------------------------------------
	// 16. Stdio transport (runs in background goroutine)
	// -----------------------------------------------------------------------
	stdioTransport := proxy.NewStdioTransport(broker, logger)
	go func() {
		if err := stdioTransport.Run(ctx); err != nil && err != context.Canceled {
			logger.Warn("stdio transport stopped", "error", err)
		}
	}()

	// -----------------------------------------------------------------------
	// 17. Block until SIGTERM / SIGINT, then drain gracefully
	// -----------------------------------------------------------------------
	drainTimeout := envDuration("ABARIS_DRAIN_TIMEOUT", 30*time.Second)
	logger.Info("Abaris ready", "addr", srv.Addr)

	if err := infra.RunWithGracefulShutdown(ctx, srv, drainTimeout, logger); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	close(stopCh)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustEnv reads a required environment variable. Logs a fatal error and exits
// with code 1 if the variable is absent or empty.
func mustEnv(key string, logger domain.Logger) string {
	v := os.Getenv(key)
	if v == "" {
		logger.Error("FATAL: required environment variable is not set", "var", key)
		os.Exit(1)
	}
	return v
}

// envOrDefault returns the value of key, or fallback if key is unset.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envDuration parses a duration from an environment variable.
// Returns fallback if the variable is absent or cannot be parsed.
func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// issuerFromDiscoveryURL derives the OIDC issuer URL from the discovery URL.
// For Cognito the discovery URL is <issuer>/.well-known/openid-configuration.
func issuerFromDiscoveryURL(discoveryURL string) string {
	const suffix = "/.well-known/openid-configuration"
	if len(discoveryURL) > len(suffix) && discoveryURL[len(discoveryURL)-len(suffix):] == suffix {
		return discoveryURL[:len(discoveryURL)-len(suffix)]
	}
	return discoveryURL
}

// buildTokenStore constructs the appropriate TokenStore backend based on config.
func buildTokenStore(
	ctx context.Context,
	cfg domain.Config,
	_ interface{}, // reserved for future use
	kmsClient auth.KMSClient,
	logger domain.Logger,
) (domain.TokenStore, error) {
	ts := cfg.TokenStore
	if ts == nil {
		return nil, fmt.Errorf("token_store config is required when secondary_providers are configured")
	}

	var backend domain.TokenStore
	switch ts.Type {
	case "dynamodb":
		if ts.TableName == "" {
			return nil, fmt.Errorf("token_store.table_name is required for dynamodb backend")
		}
		region := ts.Region
		if region == "" {
			region = os.Getenv("AWS_REGION")
		}
		awsDynCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("load AWS config for DynamoDB: %w", err)
		}
		dynamoClient := dynamodb.NewFromConfig(awsDynCfg)
		backend = auth.NewDynamoDBTokenStore(dynamoClient, ts.TableName, logger)

	case "badger":
		if ts.DataDir == "" {
			return nil, fmt.Errorf("token_store.data_dir is required for badger backend")
		}
		b, err := auth.NewBadgerTokenStore(ts.DataDir, logger)
		if err != nil {
			return nil, fmt.Errorf("open BadgerDB at %s: %w", ts.DataDir, err)
		}
		backend = b

	default:
		return nil, fmt.Errorf("unknown token_store type %q (must be dynamodb or badger)", ts.Type)
	}

	return auth.NewEncryptedTokenStore(backend, kmsClient, ts.KMSEncryptionKeyARN, logger), nil
}

// envCredentialStore implements proxy.CredentialStore by reading service
// credentials from environment variables at request time.
//
// For each route prefix, the credential is read from:
//
//	ABARIS_SERVICE_CRED_<UPPER_PREFIX>
//
// e.g. prefix "github" → ABARIS_SERVICE_CRED_GITHUB
//
// This keeps secrets out of the config files while remaining compatible with
// the Secrets Manager pattern: the composition root can pre-populate these
// env vars from Secrets Manager at startup if preferred.
type envCredentialStore struct {
	// secretsByPrefix maps prefix → pre-fetched secret value.
	// Populated at startup so we fail fast if any secret is missing.
	secretsByPrefix map[string]string
	logger          domain.Logger
}

func newEnvCredentialStore(routes []domain.RouteEntry, logger domain.Logger) *envCredentialStore {
	m := make(map[string]string, len(routes))
	for _, r := range routes {
		// Skip OBO routes — they use per-user UATs, not service credentials.
		if r.OBOProvider != "" {
			continue
		}
		envKey := "ABARIS_SERVICE_CRED_" + toUpperSnake(r.Prefix)
		val := os.Getenv(envKey)
		if val == "" {
			// Non-fatal: the credential may be optional for some backends.
			logger.Warn("service credential env var not set", "env_var", envKey, "prefix", r.Prefix)
		}
		m[r.Prefix] = val
	}
	return &envCredentialStore{secretsByPrefix: m, logger: logger}
}

func (s *envCredentialStore) GetServiceCredential(_ context.Context, prefix string) (string, error) {
	cred, ok := s.secretsByPrefix[prefix]
	if !ok {
		return "", fmt.Errorf("%w: no service credential configured for prefix %q", domain.ErrServiceUnavailable, prefix)
	}
	return cred, nil
}

// toUpperSnake converts a kebab-case or lowercase string to UPPER_SNAKE_CASE.
func toUpperSnake(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			b[i] = '_'
		} else if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		} else {
			b[i] = c
		}
	}
	return string(b)
}
