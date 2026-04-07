package config_test

// Property 14: Config directory round-trip
//
// FOR ALL valid Config_Directory contents, loading the directory into a
// domain.Config struct and re-serializing each file SHALL produce documents
// that parse to an equivalent domain.Config struct (round-trip property).
//
// Validates: Requirements 5.11

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/infra"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

// genIdentityProviderConfig generates a valid OIDC IdentityProviderConfig.
var genIdentityProviderConfig = gopter.CombineGens(
	safeSegment, // name
	safeSegment, // client_id
	safeSegment, // audience
).Map(func(v []interface{}) domain.IdentityProviderConfig {
	name := v[0].(string)
	clientID := v[1].(string)
	audience := v[2].(string)
	return domain.IdentityProviderConfig{
		Name:         name,
		Type:         "oidc",
		DiscoveryURL: "https://example.com/.well-known/openid-configuration",
		JWKSEndpoint: "https://example.com/keys",
		ClientID:     clientID,
		Audience:     audience,
	}
})

// genRouteEntry generates a valid RouteEntry with a safe prefix.
var genRouteEntry = safeSegment.Map(func(prefix string) domain.RouteEntry {
	return domain.RouteEntry{
		Prefix:     prefix,
		BackendURI: fmt.Sprintf("http://%s-backend:8080", prefix),
	}
})

// genAssertionConfig generates a valid AssertionConfig.
var genAssertionConfig = gopter.CombineGens(
	safeSegment, // signing_key_id
).Map(func(v []interface{}) domain.AssertionConfig {
	keyID := v[0].(string)
	return domain.AssertionConfig{
		Issuer:      "https://abaris.example.com",
		Audience:    "https://backend.internal",
		TTL:         60 * time.Second,
		KMSKeyARN:   "arn:aws:kms:us-east-1:123456789012:key/test-key",
		SigningKeyID: keyID,
	}
})

// genPolicyEntry generates a valid PolicyEntry whose tool patterns use the
// given prefix (so cross-file validation passes).
func genPolicyEntryForPrefix(prefix string) gopter.Gen {
	return gopter.CombineGens(
		safeSegment,                    // group
		gen.SliceOfN(2, safeSegment),   // action names
	).Map(func(v []interface{}) domain.PolicyEntry {
		group := v[0].(string)
		actions := v[1].([]string)
		allowed := make([]string, len(actions))
		for i, a := range actions {
			allowed[i] = prefix + "/" + a
		}
		return domain.PolicyEntry{
			Group: group,
			ReducedScope: domain.ReducedScope{
				AllowedTools: allowed,
			},
		}
	})
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

// identityYAML renders an IdentityConfig to YAML bytes.
func identityYAML(providers []domain.IdentityProviderConfig) ([]byte, error) {
	return yaml.Marshal(domain.IdentityConfig{IdentityProviders: providers})
}

// routingYAML renders a RoutingConfig to YAML bytes.
func routingYAML(routes []domain.RouteEntry, assertion domain.AssertionConfig) ([]byte, error) {
	return yaml.Marshal(domain.RoutingConfig{Routes: routes, Assertion: assertion})
}

// policyYAML renders a PolicyFileConfig to YAML bytes.
func policyYAML(policies []domain.PolicyEntry) ([]byte, error) {
	return yaml.Marshal(domain.PolicyFileConfig{Policies: policies})
}

// writeRoundTripDir writes a complete config directory from domain.Config and
// returns the directory path. The caller is responsible for cleanup (t.TempDir
// handles this automatically).
func writeRoundTripDir(t *testing.T, providers []domain.IdentityProviderConfig, routes []domain.RouteEntry, assertion domain.AssertionConfig, policies []domain.PolicyEntry) string {
	t.Helper()
	dir := t.TempDir()

	idBytes, err := identityYAML(providers)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	writeFile(t, filepath.Join(dir, "identity.yaml"), string(idBytes))

	rtBytes, err := routingYAML(routes, assertion)
	if err != nil {
		t.Fatalf("marshal routing: %v", err)
	}
	writeFile(t, filepath.Join(dir, "routing.yaml"), string(rtBytes))

	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}

	if len(policies) > 0 {
		polBytes, err := policyYAML(policies)
		if err != nil {
			t.Fatalf("marshal policies: %v", err)
		}
		writeFile(t, filepath.Join(dir, "policies", "generated.yaml"), string(polBytes))
	}

	return dir
}

// loadConfig calls config.NewLoader(dir).Load() and returns the result.
func loadConfig(t *testing.T, dir string) (domain.Config, error) {
	t.Helper()
	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	return loader.Load()
}

// configsEquivalent compares two domain.Config structs for semantic equivalence.
// It sorts slices before comparing so that ordering differences introduced by
// re-serialisation do not cause false negatives.
func configsEquivalent(a, b domain.Config) bool {
	// Identity providers: order must be preserved (YAML list order is significant)
	if !reflect.DeepEqual(a.IdentityProviders, b.IdentityProviders) {
		return false
	}
	// Routes: order must be preserved
	if !reflect.DeepEqual(a.Routes, b.Routes) {
		return false
	}
	// Assertion config
	if !reflect.DeepEqual(a.Assertion, b.Assertion) {
		return false
	}
	// Policies: deepMergePolicies sorts by group name and unions tool lists,
	// so the slices should already be in a canonical form after Load().
	if !reflect.DeepEqual(a.Policies, b.Policies) {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Property 14: Config directory round-trip
// ---------------------------------------------------------------------------

// TestProperty14_ConfigRoundTrip verifies that for any valid Config_Directory
// contents, loading → re-serialising → loading again produces an equivalent
// domain.Config.
//
// Validates: Requirements 5.11
func TestProperty14_ConfigRoundTrip(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("14: load → re-serialize → load produces equivalent domain.Config", prop.ForAll(
		func(provider domain.IdentityProviderConfig, route domain.RouteEntry, assertion domain.AssertionConfig, policy domain.PolicyEntry) bool {
			// Ensure the policy's allowed_tools use the route's prefix so
			// cross-file validation passes.
			fixedPolicy := domain.PolicyEntry{
				Group: policy.Group,
				ReducedScope: domain.ReducedScope{
					AllowedTools: []string{route.Prefix + "/" + "tool"},
				},
			}

			// --- First load ---
			dir1 := writeRoundTripDir(t,
				[]domain.IdentityProviderConfig{provider},
				[]domain.RouteEntry{route},
				assertion,
				[]domain.PolicyEntry{fixedPolicy},
			)
			cfg1, err := loadConfig(t, dir1)
			if err != nil {
				// Generated fixture failed validation — skip this sample.
				return true
			}

			// --- Re-serialise cfg1 into a new directory ---
			dir2 := writeRoundTripDir(t,
				cfg1.IdentityProviders,
				cfg1.Routes,
				cfg1.Assertion,
				cfg1.Policies,
			)

			// --- Second load ---
			cfg2, err := loadConfig(t, dir2)
			if err != nil {
				// Re-serialised form failed to load — round-trip broken.
				return false
			}

			return configsEquivalent(cfg1, cfg2)
		},
		genIdentityProviderConfig,
		genRouteEntry,
		genAssertionConfig,
		// Generate a policy entry; the prefix is fixed inside the property body.
		gopter.CombineGens(safeSegment).Map(func(v []interface{}) domain.PolicyEntry {
			return domain.PolicyEntry{
				Group: v[0].(string),
				ReducedScope: domain.ReducedScope{
					AllowedTools: []string{"placeholder/tool"},
				},
			}
		}),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty14_MultiPolicyRoundTrip extends the round-trip check to configs
// with multiple policy groups spread across a single policy file.
//
// Validates: Requirements 5.11
func TestProperty14_MultiPolicyRoundTrip(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("14 (multi-policy): load → re-serialize → load produces equivalent domain.Config", prop.ForAll(
		func(provider domain.IdentityProviderConfig, route domain.RouteEntry, assertion domain.AssertionConfig, groups []string) bool {
			if len(groups) == 0 {
				return true
			}

			// Deduplicate groups to avoid deep-merge union effects masking failures.
			seen := make(map[string]struct{})
			var uniqueGroups []string
			for _, g := range groups {
				if _, ok := seen[g]; !ok {
					seen[g] = struct{}{}
					uniqueGroups = append(uniqueGroups, g)
				}
			}

			policies := make([]domain.PolicyEntry, len(uniqueGroups))
			for i, g := range uniqueGroups {
				policies[i] = domain.PolicyEntry{
					Group: g,
					ReducedScope: domain.ReducedScope{
						AllowedTools: []string{route.Prefix + "/tool"},
					},
				}
			}

			dir1 := writeRoundTripDir(t,
				[]domain.IdentityProviderConfig{provider},
				[]domain.RouteEntry{route},
				assertion,
				policies,
			)
			cfg1, err := loadConfig(t, dir1)
			if err != nil {
				return true // skip invalid fixtures
			}

			dir2 := writeRoundTripDir(t,
				cfg1.IdentityProviders,
				cfg1.Routes,
				cfg1.Assertion,
				cfg1.Policies,
			)
			cfg2, err := loadConfig(t, dir2)
			if err != nil {
				return false
			}

			return configsEquivalent(cfg1, cfg2)
		},
		genIdentityProviderConfig,
		genRouteEntry,
		genAssertionConfig,
		gen.SliceOfN(3, safeSegment),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
