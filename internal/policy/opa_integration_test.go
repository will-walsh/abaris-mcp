//go:build integration

// Package policy_test contains integration tests for OPA bundle loading and hot-reload.
//
// These tests write real OPA bundles to a temp directory, load them via
// policy.New, evaluate permit/deny decisions, and verify that hot-reload
// atomically swaps the active policy without a restart.
//
// Run with: go test -tags integration ./internal/policy/...
//
// Validates: Requirements 3.2, 3.6
package policy_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/policy"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeBundle writes a minimal OPA bundle (manifest + abaris.rego) to dir.
// regoContent is the full Rego source to write as policies/abaris.rego.
func writeBundle(t *testing.T, dir string, regoContent string) {
	t.Helper()

	manifest := `{"revision":"test","roots":["abaris"]}`
	if err := os.WriteFile(filepath.Join(dir, ".manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write .manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "abaris.rego"), []byte(regoContent), 0o644); err != nil {
		t.Fatalf("write abaris.rego: %v", err)
	}
}

// toolCallFor builds a ToolCall whose Params encode the given tool name.
func toolCallFor(name string) domain.ToolCall {
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{}})
	return domain.ToolCall{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
}

// integrationLogger satisfies domain.Logger for integration tests.
type integrationLogger struct{ t *testing.T }

func (l integrationLogger) Info(msg string, args ...any)  { l.t.Logf("INFO  %s %v", msg, args) }
func (l integrationLogger) Warn(msg string, args ...any)  { l.t.Logf("WARN  %s %v", msg, args) }
func (l integrationLogger) Error(msg string, args ...any) { l.t.Logf("ERROR %s %v", msg, args) }
func (l integrationLogger) Debug(msg string, args ...any) { l.t.Logf("DEBUG %s %v", msg, args) }

// permitRego is a Rego bundle that permits any tool call for the "developers" group.
const permitRego = `package abaris.authz

import rego.v1

default allow := false
default deny_reason := "no policy permits this tool call for the caller's groups"
default matched_rule := ""

known_operations := {"read", "write", "delete"}

operation_known if {
	known_operations[input.operation]
}

caller_groups := {g | g := input.groups[_]}

glob_match(pattern, name) if {
	glob.match(pattern, ["/"], name)
}

tool_denied if {
	some i
	entry := data.policies[i]
	caller_groups[entry.group]
	some j
	pattern := entry.reduced_scope.denied_tools[j]
	glob_match(pattern, input.tool_name)
}

allow if {
	operation_known
	not tool_denied
	some i
	entry := data.policies[i]
	caller_groups[entry.group]
	some j
	pattern := entry.reduced_scope.allowed_tools[j]
	glob_match(pattern, input.tool_name)
}

matched_rule := rule_id if {
	allow
	some i
	entry := data.policies[i]
	caller_groups[entry.group]
	some j
	pattern := entry.reduced_scope.allowed_tools[j]
	glob_match(pattern, input.tool_name)
	not tool_denied
	rule_id := concat(" -> ", [entry.group, pattern])
}

deny_reason := "unauthorized: no policy permits this tool call for the caller's groups" if {
	not allow
	operation_known
}

deny_reason := "unauthorized: unknown operation type; deny-by-default applied" if {
	not allow
	not operation_known
}
`

// denyAllRego is a Rego bundle that denies every tool call (allow is always false).
const denyAllRego = `package abaris.authz

import rego.v1

default allow := false
default deny_reason := "all tool calls denied by updated policy"
default matched_rule := ""
`

// ---------------------------------------------------------------------------
// Test 1: Bundle loading — permit decision
//
// Create a valid OPA bundle in a temp dir, load it, evaluate a permit decision.
//
// Validates: Requirements 3.2
// ---------------------------------------------------------------------------

func TestOPABundleLoading_PermitDecision(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, permitRego)

	policies := []domain.PolicyEntry{
		{
			Group: "developers",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/*"},
			},
		},
	}

	ctx := context.Background()
	adapter, err := policy.New(ctx, dir, policies, integrationLogger{t})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	identity := domain.IdentityContext{
		UserID: "alice",
		Groups: []string{"developers"},
	}
	call := toolCallFor("github/get-repo")

	decision, err := adapter.Evaluate(ctx, identity, call)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Permitted {
		t.Errorf("expected Permitted=true, got false; DenialReason=%q", decision.DenialReason)
	}
	if decision.MatchedRuleID == "" {
		t.Error("expected non-empty MatchedRuleID for permitted decision")
	}
}

// ---------------------------------------------------------------------------
// Test 2: Bundle loading — deny decision
//
// Create a valid OPA bundle in a temp dir, load it, evaluate a deny decision.
//
// Validates: Requirements 3.2
// ---------------------------------------------------------------------------

func TestOPABundleLoading_DenyDecision(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, permitRego)

	policies := []domain.PolicyEntry{
		{
			Group: "developers",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/*"},
			},
		},
	}

	ctx := context.Background()
	adapter, err := policy.New(ctx, dir, policies, integrationLogger{t})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	// Caller belongs to a group not in the policy — should be denied.
	identity := domain.IdentityContext{
		UserID: "bob",
		Groups: []string{"unknown-group"},
	}
	call := toolCallFor("github/get-repo")

	decision, err := adapter.Evaluate(ctx, identity, call)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Permitted {
		t.Error("expected Permitted=false for caller with no matching group")
	}
	if decision.DenialReason == "" {
		t.Error("expected non-empty DenialReason for denied decision")
	}
}

// ---------------------------------------------------------------------------
// Test 3: Hot-reload — updated bundle that denies takes effect
//
// Load an initial bundle that permits a tool call, then write an updated bundle
// that denies it, trigger reload via StartHotReload, verify the new policy
// takes effect.
//
// Validates: Requirements 3.6
// ---------------------------------------------------------------------------

func TestOPAHotReload_UpdatedBundleDenies(t *testing.T) {
	dir := t.TempDir()

	// Initial bundle: permits developers.
	writeBundle(t, dir, permitRego)

	policies := []domain.PolicyEntry{
		{
			Group: "developers",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/*"},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adapter, err := policy.New(ctx, dir, policies, integrationLogger{t})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	identity := domain.IdentityContext{
		UserID: "alice",
		Groups: []string{"developers"},
	}
	call := toolCallFor("github/get-repo")

	// Verify initial policy permits.
	decision, err := adapter.Evaluate(ctx, identity, call)
	if err != nil {
		t.Fatalf("initial Evaluate: %v", err)
	}
	if !decision.Permitted {
		t.Fatalf("initial policy should permit; DenialReason=%q", decision.DenialReason)
	}

	// Start hot-reload with a short interval.
	const reloadInterval = 50 * time.Millisecond
	go adapter.StartHotReload(ctx, reloadInterval)

	// Overwrite the bundle with a deny-all policy.
	writeBundle(t, dir, denyAllRego)

	// Wait long enough for at least two reload cycles.
	deadline := time.Now().Add(2 * time.Second)
	var reloaded bool
	for time.Now().Before(deadline) {
		time.Sleep(reloadInterval * 2)
		d, evalErr := adapter.Evaluate(ctx, identity, call)
		if evalErr != nil {
			t.Fatalf("Evaluate during hot-reload wait: %v", evalErr)
		}
		if !d.Permitted {
			reloaded = true
			break
		}
	}

	if !reloaded {
		t.Error("hot-reload did not pick up the deny-all bundle within the deadline")
	}
}

// ---------------------------------------------------------------------------
// Test 4: Hot-reload — invalid bundle update is rejected, previous policy
// remains active.
//
// Validates: Requirements 3.6
// ---------------------------------------------------------------------------

func TestOPAHotReload_InvalidBundleRejected(t *testing.T) {
	dir := t.TempDir()

	// Initial bundle: permits developers.
	writeBundle(t, dir, permitRego)

	policies := []domain.PolicyEntry{
		{
			Group: "developers",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/*"},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adapter, err := policy.New(ctx, dir, policies, integrationLogger{t})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	identity := domain.IdentityContext{
		UserID: "alice",
		Groups: []string{"developers"},
	}
	call := toolCallFor("github/get-repo")

	// Verify initial policy permits.
	decision, err := adapter.Evaluate(ctx, identity, call)
	if err != nil {
		t.Fatalf("initial Evaluate: %v", err)
	}
	if !decision.Permitted {
		t.Fatalf("initial policy should permit; DenialReason=%q", decision.DenialReason)
	}

	// Start hot-reload with a short interval.
	const reloadInterval = 50 * time.Millisecond
	go adapter.StartHotReload(ctx, reloadInterval)

	// Overwrite abaris.rego with syntactically invalid Rego.
	invalidRego := `package abaris.authz THIS IS NOT VALID REGO !!!`
	if err := os.WriteFile(filepath.Join(dir, "abaris.rego"), []byte(invalidRego), 0o644); err != nil {
		t.Fatalf("write invalid rego: %v", err)
	}

	// Wait for several reload cycles to pass.
	time.Sleep(reloadInterval * 6)

	// The previous (permit) policy must still be active.
	decision, err = adapter.Evaluate(ctx, identity, call)
	if err != nil {
		t.Fatalf("Evaluate after invalid bundle: %v", err)
	}
	if !decision.Permitted {
		t.Errorf("previous policy should still be active after invalid bundle; DenialReason=%q", decision.DenialReason)
	}
}
