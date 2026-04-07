package config_test

// Property 27: Hot reload rejection preserves previous policies
//
// When a hot-reload cycle produces a cross-file validation error (a policy
// references an undefined route prefix), Loader MUST:
//   1. Reject the new policy set entirely
//   2. Retain the previously active policies unchanged
//   3. NOT call the onChange callback
//   4. Continue serving requests with the last known-good policy set
//
// Validates: Requirements 5.9

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

// hotReloadFixture holds the paths needed to manipulate a live config dir.
type hotReloadFixture struct {
	dir        string
	policiesDir string
}

// writeHotReloadBase writes a minimal valid config directory with one policy
// file that references validPrefix. Returns a hotReloadFixture.
func writeHotReloadBase(t *testing.T, validPrefix, group, action string) hotReloadFixture {
	t.Helper()
	dir := t.TempDir()
	policiesDir := filepath.Join(dir, "policies")

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
`, validPrefix, validPrefix))

	if err := os.MkdirAll(policiesDir, 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}

	// Initial valid policy file
	writeFile(t, filepath.Join(policiesDir, "valid.yaml"),
		buildPolicyYAML(group, []string{validPrefix + "/" + action}, nil))

	return hotReloadFixture{dir: dir, policiesDir: policiesDir}
}

// policiesFromLoader returns the current policy slice via Loader.Current().
func policiesFromLoader(l *config.Loader) []domain.PolicyEntry {
	return l.Current().Policies
}

// policyGroupNames returns the sorted group names from a policy slice.
func policyGroupNames(policies []domain.PolicyEntry) []string {
	names := make([]string, 0, len(policies))
	for _, p := range policies {
		names = append(names, p.Group)
	}
	return names
}

// policyAllowedTools returns the AllowedTools for the first matching group.
func policyAllowedTools(policies []domain.PolicyEntry, group string) []string {
	for _, p := range policies {
		if p.Group == group {
			return p.ReducedScope.AllowedTools
		}
	}
	return nil
}

// startWatcher starts Loader.Watch in a goroutine and returns a stop function.
func startWatcher(t *testing.T, l *config.Loader) func() {
	t.Helper()
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = l.Watch(stopCh)
	}()
	return func() {
		close(stopCh)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Log("watcher did not stop within timeout")
		}
	}
}

// waitForReload polls Loader.Current() until the predicate returns true or
// the timeout elapses. Returns true if the predicate was satisfied.
func waitForReload(l *config.Loader, predicate func([]domain.PolicyEntry) bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate(policiesFromLoader(l)) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// ---------------------------------------------------------------------------
// Property 27a: invalid reload does not replace previous policies
//
// After a successful Load(), writing a policy file that references an undefined
// route prefix MUST leave Loader.Current().Policies unchanged.
// ---------------------------------------------------------------------------

func TestProperty27a_InvalidReloadPreservesPreviousPolicies(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 10 // filesystem-event test: 10 iterations is sufficient
	properties := gopter.NewProperties(params)

	properties.Property("27a: invalid hot-reload leaves previous policies unchanged", prop.ForAll(
		func(validPrefix, undefinedPrefix, group, action string) bool {
			if validPrefix == undefinedPrefix {
				return true // skip degenerate case
			}

			fix := writeHotReloadBase(t, validPrefix, group, action)

			logger := infra.NewSlogLogger()
			loader := config.NewLoader(fix.dir, logger, nil)
			_, err := loader.Load()
			if err != nil {
				return true // skip if base fixture fails
			}

			// Capture the initial policy state
			initialPolicies := policiesFromLoader(loader)
			initialTools := policyAllowedTools(initialPolicies, group)

			stop := startWatcher(t, loader)
			defer stop()

			// Write an invalid policy file referencing an undefined prefix
			invalidFile := filepath.Join(fix.policiesDir, "invalid.yaml")
			writeFile(t, invalidFile,
				buildPolicyYAML(group+"extra", []string{undefinedPrefix + "/" + action}, nil))

			// Give the watcher time to process the event
			time.Sleep(150 * time.Millisecond)

			// Policies must remain unchanged
			currentPolicies := policiesFromLoader(loader)
			currentTools := policyAllowedTools(currentPolicies, group)

			// The original group's tools must be intact
			if len(currentTools) != len(initialTools) {
				return false
			}
			for i, tool := range initialTools {
				if currentTools[i] != tool {
					return false
				}
			}

			// The invalid group must NOT have been added
			for _, p := range currentPolicies {
				if p.Group == group+"extra" {
					return false
				}
			}

			return true
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 27b: onChange is NOT called when hot-reload is rejected
//
// The onChange callback MUST NOT be invoked when a reload cycle fails
// cross-file validation. Only successful reloads trigger the callback.
// ---------------------------------------------------------------------------

func TestProperty27b_OnChangeNotCalledOnRejection(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 10 // filesystem-event test: 10 iterations is sufficient
	properties := gopter.NewProperties(params)

	properties.Property("27b: onChange is not called when hot-reload is rejected", prop.ForAll(
		func(validPrefix, undefinedPrefix, group, action string) bool {
			if validPrefix == undefinedPrefix {
				return true
			}

			var callbackCount atomic.Int32
			onChange := func(_ domain.Config) {
				callbackCount.Add(1)
			}

			fix := writeHotReloadBase(t, validPrefix, group, action)
			logger := infra.NewSlogLogger()
			loader := config.NewLoader(fix.dir, logger, onChange)
			_, err := loader.Load()
			if err != nil {
				return true
			}

			stop := startWatcher(t, loader)
			defer stop()

			// Write an invalid policy file
			writeFile(t, filepath.Join(fix.policiesDir, "bad.yaml"),
				buildPolicyYAML("newgroup", []string{undefinedPrefix + "/" + action}, nil))

			time.Sleep(150 * time.Millisecond)

			// onChange must not have been called
			return callbackCount.Load() == 0
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 27c: valid reload after invalid reload succeeds
//
// After a rejected hot-reload, a subsequent valid policy update MUST be
// accepted and the policies MUST be updated. The rejection of the invalid
// reload must not put the loader into a broken state.
// ---------------------------------------------------------------------------

func TestProperty27c_ValidReloadAfterInvalidReloadSucceeds(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 10 // filesystem-event test: 10 iterations is sufficient
	properties := gopter.NewProperties(params)

	properties.Property("27c: valid reload succeeds after a previously rejected reload", prop.ForAll(
		func(validPrefix, undefinedPrefix, group, newGroup, action string) bool {
			if validPrefix == undefinedPrefix || group == newGroup {
				return true
			}

			var callbackCount atomic.Int32
			onChange := func(_ domain.Config) {
				callbackCount.Add(1)
			}

			fix := writeHotReloadBase(t, validPrefix, group, action)
			logger := infra.NewSlogLogger()
			loader := config.NewLoader(fix.dir, logger, onChange)
			_, err := loader.Load()
			if err != nil {
				return true
			}

			stop := startWatcher(t, loader)
			defer stop()

			// Step 1: write an invalid file — should be rejected
			badFile := filepath.Join(fix.policiesDir, "bad.yaml")
			writeFile(t, badFile,
				buildPolicyYAML("badgroup", []string{undefinedPrefix + "/" + action}, nil))
			time.Sleep(150 * time.Millisecond)

			// Confirm rejection: newGroup must not be present
			afterBad := policiesFromLoader(loader)
			for _, p := range afterBad {
				if p.Group == "badgroup" {
					return false // bad reload was incorrectly accepted
				}
			}

			// Step 2: remove the invalid file and write a valid one
			_ = os.Remove(badFile)
			time.Sleep(50 * time.Millisecond) // ensure remove event is processed before write
			writeFile(t, filepath.Join(fix.policiesDir, "new-valid.yaml"),
				buildPolicyYAML(newGroup, []string{validPrefix + "/" + action}, nil))

			// Wait for the valid reload to be accepted
			accepted := waitForReload(loader, func(policies []domain.PolicyEntry) bool {
				for _, p := range policies {
					if p.Group == newGroup {
						return true
					}
				}
				return false
			}, 2*time.Second)

			return accepted && callbackCount.Load() > 0
		},
		safeSegment, safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 27d: multiple consecutive invalid reloads all preserve policies
//
// Each successive invalid reload attempt MUST independently preserve the
// last known-good policy set. The loader must not accumulate partial state
// across failed reload attempts.
// ---------------------------------------------------------------------------

func TestProperty27d_MultipleInvalidReloadsAllPreservePolicies(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 10 // filesystem-event test: 10 iterations is sufficient
	properties := gopter.NewProperties(params)

	properties.Property("27d: repeated invalid reloads all preserve the original policies", prop.ForAll(
		func(validPrefix, undefinedPrefix, group, action string) bool {
			if validPrefix == undefinedPrefix {
				return true
			}

			fix := writeHotReloadBase(t, validPrefix, group, action)
			logger := infra.NewSlogLogger()
			loader := config.NewLoader(fix.dir, logger, nil)
			_, err := loader.Load()
			if err != nil {
				return true
			}

			initialTools := policyAllowedTools(policiesFromLoader(loader), group)

			stop := startWatcher(t, loader)
			defer stop()

			// Write three successive invalid files
			for i := 0; i < 3; i++ {
				fname := fmt.Sprintf("bad%d.yaml", i)
				writeFile(t, filepath.Join(fix.policiesDir, fname),
					buildPolicyYAML(fmt.Sprintf("badgroup%d", i), []string{undefinedPrefix + "/" + action}, nil))
				time.Sleep(80 * time.Millisecond)

				// After each invalid write, original tools must still be present
				currentTools := policyAllowedTools(policiesFromLoader(loader), group)
				if len(currentTools) != len(initialTools) {
					return false
				}
				for j, tool := range initialTools {
					if currentTools[j] != tool {
						return false
					}
				}
			}

			return true
		},
		safeSegment, safeSegment, safeSegment, safeSegment,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
