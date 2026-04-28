// Package domain contains all core types, interfaces, and pure functions for
// Abaris. It has zero infrastructure imports — no AWS SDK, no OIDC/SAML
// libraries, no OPA SDK. All infrastructure adapters depend on this package,
// never the reverse.
package domain

import (
	"encoding/json"
	"time"
)

// ToolCall is the structured internal representation of an MCP JSON-RPC 2.0
// tool invocation request.
type ToolCall struct {
	JSONRPC string          `json:"jsonrpc"`          // always "2.0"
	ID      any             `json:"id"`               // string | number | null
	Method  string          `json:"method"`           // e.g. "tools/call"
	Params  json.RawMessage `json:"params,omitempty"` // raw params preserved for forwarding
}

// IdentityContext holds the normalized identity attributes for an authenticated
// caller. Produced by IdentityService after validating an OIDC token or SAML
// assertion. Replaces any provider-specific claim format.
type IdentityContext struct {
	UserID       string   `json:"user_id"`
	Email        string   `json:"email"`
	Groups       []string `json:"groups"`
	Entitlements []string `json:"entitlements"`
	Provider     string   `json:"provider"` // name of the identity provider
}

// PolicyDecision is the result of a PolicyEngine evaluation.
type PolicyDecision struct {
	Permitted     bool
	MatchedRuleID string // identifier of the Rego rule (or policy entry) that matched
	DenialReason  string // human-readable reason when Permitted == false
}

// DryRunResult is the outcome of a DryRun simulation.
type DryRunResult struct {
	Permitted     bool
	MatchedPolicy string // e.g. "developers -> github/*"
	MatchedRoute  string // e.g. "http://github-mcp-server:8080"
	DenialReason  string // non-empty when Permitted == false
}

// ReducedScope defines the set of tools a group is permitted to invoke.
type ReducedScope struct {
	AllowedTools []string `yaml:"allowed_tools" validate:"required,min=1"`
	DeniedTools  []string `yaml:"denied_tools,omitempty"`
}

// PolicyEntry associates an identity group with its reduced tool scope.
type PolicyEntry struct {
	Group        string       `yaml:"group"         validate:"required"`
	ReducedScope ReducedScope `yaml:"reduced_scope" validate:"required"`
}

// RouteEntry maps a tool-name prefix to a backend MCP server URI.
// OBOProvider, when non-empty, activates the OBO pipeline for this route
// (Phase 11). For Phase 6 (standard routes) it is always empty.
// Transport selects the backend transport protocol: "http" (default) or "sse".
// Use "sse" for backends that speak the MCP SSE protocol (e.g. api.githubcopilot.com/mcp/).
type RouteEntry struct {
	Prefix      string `yaml:"prefix"                  validate:"required"`
	BackendURI  string `yaml:"backend_uri"             validate:"required,url"`
	OBOProvider string `yaml:"obo_provider,omitempty"` // name of a SecondaryProviderConfig; empty = standard flow
	Transport   string `yaml:"transport,omitempty"`    // "http" (default) or "sse"
}

// AssertionConfig holds configuration for Identity Assertion Token minting.
type AssertionConfig struct {
	Issuer      string        `yaml:"issuer"          validate:"required,url"`
	Audience    string        `yaml:"audience"        validate:"required"`
	TTL         time.Duration `yaml:"ttl"             validate:"required"`
	KMSKeyARN   string        `yaml:"kms_key_arn"     validate:"required"`
	SigningKeyID string        `yaml:"signing_key_id,omitempty"`
}

// IdentityProviderConfig holds configuration for a single identity provider.
type IdentityProviderConfig struct {
	Name string `yaml:"name" validate:"required"`
	Type string `yaml:"type" validate:"required,oneof=oidc saml"`
	// OIDC fields
	DiscoveryURL string `yaml:"discovery_url,omitempty"`
	JWKSEndpoint string `yaml:"jwks_endpoint,omitempty"`
	ClientID     string `yaml:"client_id,omitempty"`
	Audience     string `yaml:"audience,omitempty"`
	// GroupsClaim is the JWT claim name that contains the user's groups.
	// Defaults to "groups" if empty. Use "cognito:groups" for AWS Cognito.
	GroupsClaim string `yaml:"groups_claim,omitempty"`
	// SAML fields
	MetadataURL string `yaml:"metadata_url,omitempty"`
	SPEntityID  string `yaml:"sp_entity_id,omitempty"`
	ACSURL      string `yaml:"acs_url,omitempty"`
	CertPath    string `yaml:"cert_path,omitempty"`
	KeyPath     string `yaml:"key_path,omitempty"`
}

// IdentityConfig is loaded from config/identity.yaml.
type IdentityConfig struct {
	IdentityProviders  []IdentityProviderConfig  `yaml:"identity_providers"             validate:"required,min=1,dive"`
	SecondaryProviders []SecondaryProviderConfig `yaml:"secondary_providers,omitempty"  validate:"omitempty,dive"`
	TokenStore         *TokenStoreConfig         `yaml:"token_store,omitempty"`
}

// RoutingConfig is loaded from config/routing.yaml.
type RoutingConfig struct {
	Routes    []RouteEntry    `yaml:"routes"    validate:"required,min=1,dive"`
	Assertion AssertionConfig `yaml:"assertion" validate:"required"`
}

// PolicyFileConfig is loaded from a single file in config/policies/.
type PolicyFileConfig struct {
	Policies []PolicyEntry `yaml:"policies" validate:"required,min=1,dive"`
}

// Config is the merged runtime configuration. The on-disk split
// (identity.yaml / routing.yaml / policies/*.yaml) is an implementation detail
// of config.Loader; everywhere else in the codebase only Config is used.
type Config struct {
	IdentityProviders  []IdentityProviderConfig
	SecondaryProviders []SecondaryProviderConfig
	TokenStore         *TokenStoreConfig
	Routes             []RouteEntry
	Policies           []PolicyEntry
	Assertion          AssertionConfig
}

// TokenPair holds an access token and refresh token for a given user+provider.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// SecondaryProviderConfig holds configuration for a secondary OAuth2 provider
// (e.g. GitHub OAuth App). Loaded from config/identity.yaml secondary_providers section.
type SecondaryProviderConfig struct {
	Name            string   `yaml:"name"              validate:"required"`
	Type            string   `yaml:"type"              validate:"required,oneof=oauth2"`
	AuthURL         string   `yaml:"auth_url"          validate:"required,url"`
	TokenURL        string   `yaml:"token_url"         validate:"required,url"`
	ClientID        string   `yaml:"client_id"         validate:"required"`
	ClientSecretARN string   `yaml:"client_secret_arn" validate:"required"`
	Scopes          []string `yaml:"scopes"            validate:"required,min=1"`
	// ClientSecret is resolved from Secrets Manager at startup; not in YAML.
	ClientSecret string `yaml:"-"`
}

// TokenStoreConfig holds configuration for the Token_Store backend.
// Loaded from config/identity.yaml token_store section.
type TokenStoreConfig struct {
	Type string `yaml:"type" validate:"required,oneof=dynamodb badger"`
	// DynamoDB fields
	TableName string `yaml:"table_name,omitempty"`
	Region    string `yaml:"region,omitempty"`
	// BadgerDB fields
	DataDir string `yaml:"data_dir,omitempty"`
	// KMS encryption key ARN (required for both backends)
	KMSEncryptionKeyARN string `yaml:"kms_encryption_key_arn" validate:"required"`
}
