package config_test

// Property 26: Cross-file validation rejects undefined prefixes
//
// validatePolicyRoutes (called by Loader.Load() and on every hot-reload cycle)
// MUST return an error whenever any policy pattern references a tool prefix that
// is not present in the routes table. Conversely, when every prefix referenced
// by every policy pattern IS present in the routes table, Load() MUST succeed.
//
// Validates: Requirements 5.7

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

// ---------------------------------------------------------------------------
// Fixture helpers (local to this file; safeSegment is declared in
// deep_merge_property_test.go and is visible within the same package_test).
// ---------------------------------------------------------------------------

// genDistinctSegments generates two distinct safe segments.
var genDistinctSegments = gopter.CombineGens(safeSegment, safeSegment).
	SuchThat(func(v []interface{}) bool {
		return v[0].(string) != v[1].(string)
	})

// writeValidateFixture writes a minimal config directory where the policy file
// uses the given toolPrefix in its allowed_tools patterns, and the routes table
// contains routePrefixes. Returns the temp dir path.
func writeValidateFixture(
	t *testing.T,
	group string,
	toolPrefix string,
	routePrefixes []string,
	allowedPatterns []string,
	deniedPatterns []string,
) string {
	t.Helper()
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "identity.yaml"), `
identity_providers:
  - name: test-oidc
    type: oidc
    discovery_url: https://example.com/.well-known/openid-configuration
    jwks_endpoint: https://example.com/keys
    client_id: test-client
    audience: test-audience
`)

	// Build routing.yaml with the supplied route prefixes.
	routeLines := ""
	for _, rp := range routePrefixes {
		routeLines += fmt.Sprintf("  - prefix: %s\n    backend_uri: http://%s-backend:8080\n", rp, rp)
	}
	writeFile(t, filepath.Join(dir, "routing.yaml"), fmt.Sprintf(`
routes:
%sassertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`, routeLines))

	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}

	writeFile(t, filepath.Join(dir, "policies", "test.yaml"),
		buildPolicyYAML(group, allowedPatterns, deniedPatterns))

	return dir
}

// loadExpectError calls Loader.Load() and returns true if an error was returned.
func loadExpectError(t *testing.T, dir string) bool {
	t.Helper()
	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	return err != nil
}

// loadExpectSuccess calls Loader.Load() and returns true if no error was returned.
func loadExpectSuccess(t *testing.T, dir string) bool {
	t.Helper()
	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	_, err := loader.Load()
	return err == nil
}

// ---------------------------------------------------------------------------
// Property 26a: undefined prefix in allowed_tools always causes an error
//
// For any policy whose allowed_tools contains a pattern whose prefix is NOT
// present in the routes table, Loader.Load() MUST return a non-nil error.
// ---------------------------------------------------------------------------

func TestProperty26a_UndefinedAllowedPrefixAlwaysErrors(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("26a: allowed_tools with undefined prefix always causes Load() to fail", prop.ForAll(
		func(definedPrefix, undefinedPrefix, group, action string) bool {
			if definedPrefix == undefinedPrefix {
				return true // skip degenerate case
			}

			// The policy references undefinedPrefix, but only definedPrefix is in routes.
			pattern := undefinedPrefix + "/" + action
			dir := writeValidateFixture(t, group, undefinedPrefix,
				[]string{definedPrefix},   // routes only contain definedPrefix
				[]string{pattern},         // allowed_tools references undefinedPrefix
				nil,
			)
			return loadExpectError(t, dir)
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 26b: undefined prefix in denied_tools always causes an error
//
// The same validation applies to denied_tools patterns — an undefined prefix
// there must also be rejected.
// ---------------------------------------------------------------------------

func TestProperty26b_UndefinedDeniedPrefixAlwaysErrors(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("26b: denied_tools with undefined prefix always causes Load() to fail", prop.ForAll(
		func(definedPrefix, undefinedPrefix, group, action string) bool {
			if definedPrefix == undefinedPrefix {
				return true
			}

			allowedPattern := definedPrefix + "/*"
			deniedPattern := undefinedPrefix + "/" + action

			dir := writeValidateFixture(t, group, undefinedPrefix,
				[]string{definedPrefix},
				[]string{allowedPattern},
				[]string{deniedPattern}, // denied_tools references undefinedPrefix
			)
			return loadExpectError(t, dir)
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 26c: all prefixes defined → Load() always succeeds
//
// When every prefix referenced in every policy pattern IS present in the
// routes table, validatePolicyRoutes must not return an error.
// ---------------------------------------------------------------------------

func TestProperty26c_AllPrefixesDefinedAlwaysSucceeds(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("26c: when all referenced prefixes exist in routes, Load() succeeds", prop.ForAll(
		func(prefix, group, action string) bool {
			pattern := prefix + "/" + action
			dir := writeValidateFixture(t, group, prefix,
				[]string{prefix},  // routes contain the same prefix
				[]string{pattern}, // allowed_tools references that prefix
				nil,
			)
			return loadExpectSuccess(t, dir)
		},
		safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 26d: error message identifies the offending group and prefix
//
// When validatePolicyRoutes rejects a config, the error message MUST contain
// both the group name and the undefined prefix so operators can diagnose the
// problem without reading source code.
// ---------------------------------------------------------------------------

func TestProperty26d_ErrorMessageIdentifiesGroupAndPrefix(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("26d: error message contains the offending group name and undefined prefix", prop.ForAll(
		func(definedPrefix, undefinedPrefix, group, action string) bool {
			if definedPrefix == undefinedPrefix {
				return true
			}

			pattern := undefinedPrefix + "/" + action
			dir := writeValidateFixture(t, group, undefinedPrefix,
				[]string{definedPrefix},
				[]string{pattern},
				nil,
			)

			logger := infra.NewSlogLogger()
			loader := config.NewLoader(dir, logger, nil)
			_, err := loader.Load()
			if err == nil {
				return false // expected an error
			}

			msg := err.Error()
			return strings.Contains(msg, group) && strings.Contains(msg, undefinedPrefix)
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 26e: multi-file scenario — one file valid, one file invalid
//
// Even when one policy file references only defined prefixes, if a second file
// references an undefined prefix the entire load MUST fail. Validation is
// applied to the merged policy set, not per-file.
// ---------------------------------------------------------------------------

func TestProperty26e_MultiFileOneInvalidAlwaysErrors(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("26e: one invalid file among many causes Load() to fail", prop.ForAll(
		func(definedPrefix, undefinedPrefix, groupA, groupB, action string) bool {
			if definedPrefix == undefinedPrefix || groupA == groupB {
				return true
			}

			dir := t.TempDir()

			writeFile(t, filepath.Join(dir, "identity.yaml"), `
identity_providers:
  - name: test-oidc
    type: oidc
    discovery_url: https://example.com/.well-known/openid-configuration
    jwks_endpoint: https://example.com/keys
    client_id: test-client
    audience: test-audience
`)
			writeFile(t, filepath.Join(dir, "routing.yaml"), fmt.Sprintf(`
routes:
  - prefix: %s
    backend_uri: http://%s-backend:8080
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`, definedPrefix, definedPrefix))

			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}

			// valid-group.yaml — references only the defined prefix
			writeFile(t, filepath.Join(dir, "policies", "valid-group.yaml"),
				buildPolicyYAML(groupA, []string{definedPrefix + "/" + action}, nil))

			// invalid-group.yaml — references the undefined prefix
			writeFile(t, filepath.Join(dir, "policies", "invalid-group.yaml"),
				buildPolicyYAML(groupB, []string{undefinedPrefix + "/" + action}, nil))

			return loadExpectError(t, dir)
		},
		safeSegment, safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 26f: wildcard glob patterns are validated by their prefix segment
//
// A pattern like "github/*" has prefix "github". If "github" is not in routes,
// the load MUST fail — even though the pattern uses a wildcard suffix.
// ---------------------------------------------------------------------------

func TestProperty26f_WildcardPatternPrefixIsValidated(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	// genDistinctSegments is declared in deep_merge_property_test.go
	properties.Property("26f: wildcard pattern with undefined prefix causes Load() to fail", prop.ForAll(
		func(v []interface{}) bool {
			definedPrefix := v[0].(string)
			undefinedPrefix := v[1].(string)
			group := "testgroup"

			wildcardPattern := undefinedPrefix + "/*"
			dir := writeValidateFixture(t, group, undefinedPrefix,
				[]string{definedPrefix},
				[]string{wildcardPattern},
				nil,
			)
			return loadExpectError(t, dir)
		},
		genDistinctSegments,
	))

	properties.Property("26f: wildcard pattern with defined prefix always succeeds", prop.ForAll(
		func(prefix string) bool {
			group := "testgroup"
			wildcardPattern := prefix + "/*"
			dir := writeValidateFixture(t, group, prefix,
				[]string{prefix},
				[]string{wildcardPattern},
				nil,
			)
			return loadExpectSuccess(t, dir)
		},
		gen.RegexMatch(`[a-z][a-z0-9]{1,8}`),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
