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
type RouteEntry struct {
	Prefix      string `yaml:"prefix"                  validate:"required"`
	BackendURI  string `yaml:"backend_uri"             validate:"required,url"`
	OBOProvider string `yaml:"obo_provider,omitempty"` // name of a SecondaryProviderConfig; empty = standard flow
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
	IdentityProviders []IdentityProviderConfig `yaml:"identity_providers" validate:"required,min=1,dive"`
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
	IdentityProviders []IdentityProviderConfig
	Routes            []RouteEntry
	Policies          []PolicyEntry
	Assertion         AssertionConfig
}
