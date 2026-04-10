// Package config_test contains unit tests for config.Loader validation.
//
// These tests cover:
//   - Missing required fields in identity.yaml → fatal error (Req 5.6)
//   - Invalid URLs in routing.yaml → fatal error (Req 5.6)
//   - Unrecognised provider type → fatal error (Req 5.6)
//   - Missing config directory → fatal error (Req 5.5)
//   - Cross-file validation: policy references undefined route prefix (Req 5.7)
//
// Requirements: 5.5, 5.6, 5.7
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

// TestLoader_Load_MissingConfigDir verifies that Load returns an error when
// the config directory does not exist (Req 5.5).
func TestLoader_Load_MissingConfigDir(t *testing.T) {
	logger := infra.NewSlogLogger()
	loader := config.NewLoader("/nonexistent/config/dir", logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for missing config directory, got nil")
	}
}

// TestLoader_Load_MissingIdentityYAML verifies that Load returns an error when
// identity.yaml is absent (Req 5.5).
func TestLoader_Load_MissingIdentityYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML("github"))
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML("developers", "github"))

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for missing identity.yaml, got nil")
	}
}

// TestLoader_Load_MissingRoutingYAML verifies that Load returns an error when
// routing.yaml is absent (Req 5.5).
func TestLoader_Load_MissingRoutingYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML("developers", "github"))

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for missing routing.yaml, got nil")
	}
}

// TestLoader_Load_InvalidProviderType verifies that Load returns an error when
// identity.yaml contains an unrecognised provider type (Req 5.6).
func TestLoader_Load_InvalidProviderType(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.yaml"), `
identity_providers:
  - name: bad-provider
    type: ldap
    discovery_url: https://example.com/.well-known/openid-configuration
    client_id: client-abc
    audience: api://abaris
`)
	writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML("github"))
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML("developers", "github"))

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for unrecognised provider type 'ldap', got nil")
	}
}

// TestLoader_Load_InvalidBackendURL verifies that Load returns an error when
// routing.yaml contains an invalid backend_uri (Req 5.6).
func TestLoader_Load_InvalidBackendURL(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))
	writeFile(t, filepath.Join(dir, "routing.yaml"), `
routes:
  - prefix: github
    backend_uri: "not a valid url"
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
`)
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML("developers", "github"))

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for invalid backend_uri, got nil")
	}
}

// TestLoader_Load_MissingRequiredField_IdentityProviderName verifies that Load
// returns an error when an identity provider entry is missing the required
// 'name' field (Req 5.6).
func TestLoader_Load_MissingRequiredField_IdentityProviderName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.yaml"), `
identity_providers:
  - type: oidc
    discovery_url: https://example.okta.com/.well-known/openid-configuration
    client_id: client-abc
    audience: api://abaris
`)
	writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML("github"))
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML("developers", "github"))

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for missing provider name, got nil")
	}
}

// TestLoader_Load_MissingRequiredField_RoutePrefix verifies that Load returns
// an error when a route entry is missing the required 'prefix' field (Req 5.6).
func TestLoader_Load_MissingRequiredField_RoutePrefix(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))
	writeFile(t, filepath.Join(dir, "routing.yaml"), `
routes:
  - backend_uri: http://github-mcp-server:8080
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
`)
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML("developers", "github"))

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for missing route prefix, got nil")
	}
}

// TestLoader_Load_PolicyReferencesUndefinedRoutePrefix verifies that Load
// returns an error when a policy references a route prefix not in routing.yaml
// (Req 5.7).
func TestLoader_Load_PolicyReferencesUndefinedRoutePrefix(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))
	writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML("github")) // only has "github" prefix
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Policy references "jira/*" but routing.yaml has no "jira" prefix.
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), `
policies:
  - group: developers
    reduced_scope:
      allowed_tools:
        - "jira/*"
`)

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for policy referencing undefined route prefix 'jira', got nil")
	}
}

// TestLoader_Load_ValidConfig verifies that Load succeeds with a complete,
// valid config directory (positive case).
func TestLoader_Load_ValidConfig(t *testing.T) {
	dir := writeCompleteValidDir(t, "github", "developers")

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if len(cfg.IdentityProviders) == 0 {
		t.Error("expected at least one identity provider")
	}
	if len(cfg.Routes) == 0 {
		t.Error("expected at least one route")
	}
	if len(cfg.Policies) == 0 {
		t.Error("expected at least one policy")
	}
}

// TestLoader_Load_EmptyIdentityProviders verifies that Load returns an error
// when identity.yaml has an empty identity_providers list (Req 5.6).
func TestLoader_Load_EmptyIdentityProviders(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.yaml"), `
identity_providers: []
`)
	writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML("github"))
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML("developers", "github"))

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	if err == nil {
		t.Fatal("expected error for empty identity_providers, got nil")
	}
}
