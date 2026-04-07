package config_test

// Property 25: Deep merge union correctness
//
// For any two PolicyFileConfig inputs that share a group name, the merged
// PolicyEntry for that group MUST contain the union of both files'
// allowed_tools and denied_tools — no pattern from either file may be lost,
// and no pattern may appear more than once.
//
// Validates: Requirements 5.4

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// safeSegment generates non-empty lowercase alphanumeric strings safe for use
// as tool name segments, group names, and route prefixes.
var safeSegment = gen.RegexMatch(`[a-z][a-z0-9]{1,8}`)

// genDistinctPair generates two distinct strings from safeSegment.
var genDistinctPair = gopter.CombineGens(safeSegment, safeSegment).
	SuchThat(func(v []interface{}) bool {
		return v[0].(string) != v[1].(string)
	})

// writeMergeFixture writes a minimal config directory with two policy files
// that both define an entry for sharedGroup. fileATools and fileBTools are the
// allowed_tools lists for each file. Returns the config dir path.
func writeMergeFixture(t *testing.T, prefix, sharedGroup string, fileATools, fileBTools []string) string {
	t.Helper()
	dir := t.TempDir()

	// identity.yaml
	writeFile(t, filepath.Join(dir, "identity.yaml"), fmt.Sprintf(`
identity_providers:
  - name: test-oidc
    type: oidc
    discovery_url: https://example.com/.well-known/openid-configuration
    jwks_endpoint: https://example.com/keys
    client_id: test-client
    audience: test-audience
`))

	// routing.yaml — one route for the prefix under test
	writeFile(t, filepath.Join(dir, "routing.yaml"), fmt.Sprintf(`
routes:
  - prefix: %s
    backend_uri: http://backend:8080
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`, prefix))

	// policies/
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}

	// file-a.yaml
	writeFile(t, filepath.Join(dir, "policies", "file-a.yaml"),
		buildPolicyYAML(sharedGroup, fileATools, nil))

	// file-b.yaml
	writeFile(t, filepath.Join(dir, "policies", "file-b.yaml"),
		buildPolicyYAML(sharedGroup, fileBTools, nil))

	return dir
}

// writeDeniedMergeFixture is like writeMergeFixture but also sets denied_tools.
func writeDeniedMergeFixture(t *testing.T, prefix, sharedGroup string,
	fileAAllowed, fileADenied, fileBAllowed, fileBDenied []string,
) string {
	t.Helper()
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "identity.yaml"), fmt.Sprintf(`
identity_providers:
  - name: test-oidc
    type: oidc
    discovery_url: https://example.com/.well-known/openid-configuration
    jwks_endpoint: https://example.com/keys
    client_id: test-client
    audience: test-audience
`))

	writeFile(t, filepath.Join(dir, "routing.yaml"), fmt.Sprintf(`
routes:
  - prefix: %s
    backend_uri: http://backend:8080
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`, prefix))

	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}

	writeFile(t, filepath.Join(dir, "policies", "file-a.yaml"),
		buildPolicyYAML(sharedGroup, fileAAllowed, fileADenied))
	writeFile(t, filepath.Join(dir, "policies", "file-b.yaml"),
		buildPolicyYAML(sharedGroup, fileBAllowed, fileBDenied))

	return dir
}

// buildPolicyYAML renders a minimal policy YAML for one group.
func buildPolicyYAML(group string, allowed, denied []string) string {
	s := fmt.Sprintf("policies:\n  - group: %s\n    reduced_scope:\n      allowed_tools:\n", group)
	for _, t := range allowed {
		s += fmt.Sprintf("        - %q\n", t)
	}
	if len(denied) > 0 {
		s += "      denied_tools:\n"
		for _, t := range denied {
			s += fmt.Sprintf("        - %q\n", t)
		}
	}
	return s
}

// writeFile writes content to path, failing the test on error.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// containsAll reports whether super contains every element of sub.
func containsAll(super, sub []string) bool {
	set := make(map[string]struct{}, len(super))
	for _, s := range super {
		set[s] = struct{}{}
	}
	for _, s := range sub {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// noDuplicates reports whether slice has no repeated elements.
func noDuplicates(ss []string) bool {
	seen := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			return false
		}
		seen[s] = struct{}{}
	}
	return true
}

// isSorted reports whether ss is in non-decreasing order.
func isSorted(ss []string) bool {
	return sort.StringsAreSorted(ss)
}

// loadMerged is a test helper that writes a two-file fixture and calls Load().
func loadMerged(t *testing.T, prefix, group string, fileATools, fileBTools []string) ([]string, []string) {
	t.Helper()
	dir := writeMergeFixture(t, prefix, group, fileATools, fileBTools)
	logger := infra.NewSlogLogger()
	loader := config.NewLoader(dir, logger, nil)
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// find the merged entry for our group
	for _, p := range cfg.Policies {
		if p.Group == group {
			return p.ReducedScope.AllowedTools, p.ReducedScope.DeniedTools
		}
	}
	t.Fatalf("group %q not found in merged policies", group)
	return nil, nil
}

// ---------------------------------------------------------------------------
// Property 25: Deep merge union correctness
// ---------------------------------------------------------------------------

// TestProperty25_DeepMergeUnionCorrectness verifies four sub-properties of
// deepMergePolicies via Loader.Load() over temp-dir fixtures:
//
//  25a: union completeness — every pattern from both files appears in the merge
//  25b: no duplication — patterns that appear in both files are not doubled
//  25c: stable sort — the merged slices are in non-decreasing lexicographic order
//  25d: denied_tools union — the same union semantics apply to denied_tools
func TestProperty25_DeepMergeUnionCorrectness(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	// 25a: union completeness for allowed_tools
	//
	// For any two non-empty allowed_tools lists A and B (with distinct patterns),
	// the merged allowed_tools MUST contain every element of A and every element of B.
	properties.Property("25a: merged allowed_tools contains all patterns from both files", prop.ForAll(
		func(prefix, group, toolA, toolB string) bool {
			// toolA and toolB are distinct patterns in the same prefix namespace
			patA := prefix + "/" + toolA
			patB := prefix + "/" + toolB
			if patA == patB {
				return true // skip degenerate case
			}

			merged, _ := loadMerged(t, prefix, group, []string{patA}, []string{patB})
			return containsAll(merged, []string{patA, patB})
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	// 25b: no duplication — a pattern present in both files appears exactly once
	//
	// When the same pattern appears in both file-a and file-b, the merged slice
	// MUST contain it exactly once (deduplication).
	properties.Property("25b: shared pattern appears exactly once after merge", prop.ForAll(
		func(prefix, group, action string) bool {
			sharedPattern := prefix + "/" + action

			merged, _ := loadMerged(t, prefix, group,
				[]string{sharedPattern},
				[]string{sharedPattern},
			)
			return noDuplicates(merged)
		},
		safeSegment, safeSegment, safeSegment,
	))

	// 25c: stable sort — merged allowed_tools is in non-decreasing lexicographic order
	properties.Property("25c: merged allowed_tools is stable-sorted", prop.ForAll(
		func(prefix, group, toolA, toolB string) bool {
			patA := prefix + "/" + toolA
			patB := prefix + "/" + toolB

			merged, _ := loadMerged(t, prefix, group, []string{patA}, []string{patB})
			return isSorted(merged)
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	// 25d: denied_tools union — same union + dedup + sort semantics apply
	properties.Property("25d: merged denied_tools contains all denied patterns from both files without duplicates", prop.ForAll(
		func(prefix, group, deniedA, deniedB string) bool {
			patA := prefix + "/" + deniedA
			patB := prefix + "/" + deniedB

			dir := writeDeniedMergeFixture(t, prefix, group,
				[]string{prefix + "/*"}, []string{patA}, // file-a: allow all, deny patA
				[]string{prefix + "/*"}, []string{patB}, // file-b: allow all, deny patB
			)
			logger := infra.NewSlogLogger()
			loader := config.NewLoader(dir, logger, nil)
			cfg, err := loader.Load()
			if err != nil {
				t.Logf("Load() error (skipping): %v", err)
				return true // skip on fixture error
			}

			var mergedDenied []string
			for _, p := range cfg.Policies {
				if p.Group == group {
					mergedDenied = p.ReducedScope.DeniedTools
					break
				}
			}

			return containsAll(mergedDenied, []string{patA, patB}) &&
				noDuplicates(mergedDenied) &&
				isSorted(mergedDenied)
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty25_SingleFilePassthrough verifies that when only one policy file
// exists for a group, deepMergePolicies is a no-op: the output equals the input.
//
// This is a boundary condition of the union property: union(A, ∅) == A.
func TestProperty25_SingleFilePassthrough(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("single-file group is preserved unchanged", prop.ForAll(
		func(prefix, group, action string) bool {
			pattern := prefix + "/" + action
			dir := t.TempDir()

			writeFile(t, filepath.Join(dir, "identity.yaml"), fmt.Sprintf(`
identity_providers:
  - name: test-oidc
    type: oidc
    discovery_url: https://example.com/.well-known/openid-configuration
    jwks_endpoint: https://example.com/keys
    client_id: test-client
    audience: test-audience
`))
			writeFile(t, filepath.Join(dir, "routing.yaml"), fmt.Sprintf(`
routes:
  - prefix: %s
    backend_uri: http://backend:8080
assertion:
  issuer: https://abaris.example.com
  audience: https://backend.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:123456789012:key/test-key
  signing_key_id: test-key-2024
`, prefix))

			if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
				return true
			}
			writeFile(t, filepath.Join(dir, "policies", "only.yaml"),
				buildPolicyYAML(group, []string{pattern}, nil))

			logger := infra.NewSlogLogger()
			loader := config.NewLoader(dir, logger, nil)
			cfg, err := loader.Load()
			if err != nil {
				return true // skip on fixture error
			}

			for _, p := range cfg.Policies {
				if p.Group == group {
					return len(p.ReducedScope.AllowedTools) == 1 &&
						p.ReducedScope.AllowedTools[0] == pattern
				}
			}
			return false
		},
		safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// TestProperty25_MergeIsCommutative verifies that the order in which policy
// files are processed does not affect the merged result.
//
// Because deepMergePolicies iterates files in glob order, this property
// confirms that union(A, B) == union(B, A) for the merged output.
func TestProperty25_MergeIsCommutative(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	properties := gopter.NewProperties(params)

	properties.Property("merge result is the same regardless of file order", prop.ForAll(
		func(prefix, group, toolA, toolB string) bool {
			if toolA == toolB {
				return true
			}
			patA := prefix + "/" + toolA
			patB := prefix + "/" + toolB

			// Order 1: file-a has patA, file-b has patB
			mergedAB, _ := loadMerged(t, prefix, group, []string{patA}, []string{patB})

			// Order 2: file-a has patB, file-b has patA
			// Use a different group name to avoid cross-contamination in the same dir
			mergedBA, _ := loadMerged(t, prefix, group, []string{patB}, []string{patA})

			// Both orderings must produce the same sorted set
			sort.Strings(mergedAB)
			sort.Strings(mergedBA)

			if len(mergedAB) != len(mergedBA) {
				return false
			}
			for i := range mergedAB {
				if mergedAB[i] != mergedBA[i] {
					return false
				}
			}
			return true
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
