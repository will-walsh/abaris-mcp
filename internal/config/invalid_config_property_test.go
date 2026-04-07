package config_test

// Property 15: Invalid config always causes fatal startup failure
//
// For any config directory that contains a schema validation error — a missing
// required field, an invalid URL, an unrecognised provider type, or a missing
// required file — Loader.Load() MUST return a non-nil error. The composition
// root treats a non-nil error from Load() as a fatal startup failure.
//
// Validates: Requirements 5.6

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

// validIdentityYAML returns a minimal valid identity.yaml content.
func validIdentityYAML(providerName string) string {
	return fmt.Sprintf(`
identity_providers:
  - name: %s
    type: oidc
    discovery_url: https://example.com/.well-known/openid-configuration
    jwks_endpoint: https://example.com/keys
    client_id: test-client
    audience: test-audience
`, providerName)
}

// validRoutingYAML returns a minimal valid routing.yaml content for the given prefix.
func validRoutingYAML(prefix string) string {
	return fmt.Sprintf(`
routes:
  - prefix: %s
    backend_uri: http://%s-backend:8080
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`, prefix, prefix)
}

// validPolicyYAML returns a minimal valid policy file content for the given prefix.
func validPolicyYAML(group, prefix string) string {
	return fmt.Sprintf(`
policies:
  - group: %s
    reduced_scope:
      allowed_tools:
        - "%s/*"
`, group, prefix)
}

// writeCompleteValidDir writes a fully valid config directory and returns its path.
func writeCompleteValidDir(t *testing.T, prefix, group string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))
	writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML(prefix))
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}
	writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))
	return dir
}

// loadShouldFail calls Loader.Load() and returns true if it returned an error.
func loadShouldFail(dir string) bool {
	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	return err != nil
}

// loadShouldSucceed calls Loader.Load() and returns true if it returned no error.
func loadShouldSucceed(dir string) bool {
	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	return err == nil
}

// ---------------------------------------------------------------------------
// Property 15a: missing identity.yaml always causes Load() to fail
// ---------------------------------------------------------------------------

func TestProperty15a_MissingIdentityYAMLAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("15a: absent identity.yaml always causes Load() to fail", prop.ForAll(
		func(prefix, group string) bool {
			dir := t.TempDir()
			// Deliberately omit identity.yaml
			writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML(prefix))
			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))
			return loadShouldFail(dir)
		},
		safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 15b: missing routing.yaml always causes Load() to fail
// ---------------------------------------------------------------------------

func TestProperty15b_MissingRoutingYAMLAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("15b: absent routing.yaml always causes Load() to fail", prop.ForAll(
		func(prefix, group string) bool {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))
			// Deliberately omit routing.yaml
			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))
			return loadShouldFail(dir)
		},
		safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 15c: unrecognised provider type always causes Load() to fail
//
// The identity_providers[].type field must be "oidc" or "saml". Any other
// value must be rejected by schema validation.
// ---------------------------------------------------------------------------

func TestProperty15c_UnrecognisedProviderTypeAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	// Generate strings that are not "oidc" or "saml"
	invalidType := gen.RegexMatch(`[a-z]{3,10}`).
		SuchThat(func(v interface{}) bool {
			s := v.(string)
			return s != "oidc" && s != "saml"
		})

	properties.Property("15c: unrecognised provider type always causes Load() to fail", prop.ForAll(
		func(prefix, group, badType string) bool {
			dir := t.TempDir()

			// identity.yaml with an invalid type
			writeFile(t, filepath.Join(dir, "identity.yaml"), fmt.Sprintf(`
identity_providers:
  - name: test-provider
    type: %s
    discovery_url: https://example.com/.well-known/openid-configuration
    jwks_endpoint: https://example.com/keys
    client_id: test-client
    audience: test-audience
`, badType))
			writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML(prefix))
			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))

			return loadShouldFail(dir)
		},
		safeSegment, safeSegment, invalidType,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 15d: missing required field in identity_providers always fails
//
// Each identity provider entry requires a non-empty "name" and "type".
// Omitting either must cause Load() to fail.
// ---------------------------------------------------------------------------

func TestProperty15d_MissingProviderNameAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("15d: identity provider with empty name always causes Load() to fail", prop.ForAll(
		func(prefix, group string) bool {
			dir := t.TempDir()

			// identity.yaml with name omitted (empty string fails "required" tag)
			writeFile(t, filepath.Join(dir, "identity.yaml"), `
identity_providers:
  - name: ""
    type: oidc
    discovery_url: https://example.com/.well-known/openid-configuration
    jwks_endpoint: https://example.com/keys
    client_id: test-client
    audience: test-audience
`)
			writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML(prefix))
			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))

			return loadShouldFail(dir)
		},
		safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 15e: invalid backend_uri in routing.yaml always fails
//
// RouteEntry.BackendURI has the "url" validation tag. Any non-URL value must
// be rejected.
// ---------------------------------------------------------------------------

func TestProperty15e_InvalidBackendURIAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	// Generate strings that are clearly not valid URLs (no scheme, no host)
	notAURL := gen.RegexMatch(`[a-z]{3,12}`).
		SuchThat(func(v interface{}) bool {
			s := v.(string)
			// Must not accidentally be a valid URL
			return len(s) < 10
		})

	properties.Property("15e: invalid backend_uri always causes Load() to fail", prop.ForAll(
		func(prefix, group, badURI string) bool {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))

			// routing.yaml with a non-URL backend_uri
			writeFile(t, filepath.Join(dir, "routing.yaml"), fmt.Sprintf(`
routes:
  - prefix: %s
    backend_uri: %s
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`, prefix, badURI))

			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))

			return loadShouldFail(dir)
		},
		safeSegment, safeSegment, notAURL,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 15f: empty identity_providers list always fails
//
// IdentityConfig.IdentityProviders has validate:"required,min=1". An empty
// list must be rejected.
// ---------------------------------------------------------------------------

func TestProperty15f_EmptyIdentityProvidersAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("15f: empty identity_providers list always causes Load() to fail", prop.ForAll(
		func(prefix, group string) bool {
			dir := t.TempDir()

			writeFile(t, filepath.Join(dir, "identity.yaml"), `
identity_providers: []
`)
			writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML(prefix))
			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))

			return loadShouldFail(dir)
		},
		safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 15g: empty routes list always fails
//
// RoutingConfig.Routes has validate:"required,min=1". An empty list must be
// rejected.
// ---------------------------------------------------------------------------

func TestProperty15g_EmptyRoutesAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("15g: empty routes list always causes Load() to fail", prop.ForAll(
		func(prefix, group string) bool {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))

			writeFile(t, filepath.Join(dir, "routing.yaml"), `
routes: []
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`)
			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))

			return loadShouldFail(dir)
		},
		safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 15h: missing assertion issuer always fails
//
// AssertionConfig.Issuer has validate:"required,url". An empty issuer must be
// rejected.
// ---------------------------------------------------------------------------

func TestProperty15h_MissingAssertionIssuerAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("15h: missing assertion issuer always causes Load() to fail", prop.ForAll(
		func(prefix, group string) bool {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))

			// routing.yaml with no issuer in assertion block
			writeFile(t, filepath.Join(dir, "routing.yaml"), fmt.Sprintf(`
routes:
  - prefix: %s
    backend_uri: http://%s-backend:8080
assertion:
  issuer: ""
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`, prefix, prefix))

			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), validPolicyYAML(group, prefix))

			return loadShouldFail(dir)
		},
		safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 15i: policy file with empty allowed_tools always fails
//
// ReducedScope.AllowedTools has validate:"required,min=1". An empty list must
// be rejected.
// ---------------------------------------------------------------------------

func TestProperty15i_EmptyAllowedToolsAlwaysFails(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("15i: policy entry with empty allowed_tools always causes Load() to fail", prop.ForAll(
		func(prefix, group string) bool {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "identity.yaml"), validIdentityYAML("test-oidc"))
			writeFile(t, filepath.Join(dir, "routing.yaml"), validRoutingYAML(prefix))
			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}

			// Policy file with an empty allowed_tools list
			writeFile(t, filepath.Join(dir, "policies", "test.yaml"), fmt.Sprintf(`
policies:
  - group: %s
    reduced_scope:
      allowed_tools: []
`, group))

			return loadShouldFail(dir)
		},
		safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Baseline: valid config always succeeds
//
// This is the positive counterpart to all the failure properties above.
// A fully valid config directory must always load without error.
// ---------------------------------------------------------------------------

func TestProperty15_ValidConfigAlwaysSucceeds(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("15 (baseline): fully valid config always causes Load() to succeed", prop.ForAll(
		func(prefix, group string) bool {
			dir := writeCompleteValidDir(t, prefix, group)
			return loadShouldSucceed(dir)
		},
		safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
