package policy_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/policy"
)

// bundlePath returns the absolute path to the policies/ directory at the repo root.
func bundlePath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/policy/opa_adapter_property_test.go → ../../policies
	return filepath.Join(filepath.Dir(file), "..", "..", "policies")
}

// newAdapter creates an OPAPolicyAdapter with the given policies and the real
// Rego bundle from policies/.
func newAdapter(t *testing.T, policies []domain.PolicyEntry) *policy.OPAPolicyAdapter {
	t.Helper()
	ctx := context.Background()
	a, err := policy.New(ctx, bundlePath(t), policies, noopLogger{})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return a
}

// toolCall builds a ToolCall whose Params encode the given tool name.
func toolCall(name string) domain.ToolCall {
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{}})
	return domain.ToolCall{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
}

// noopLogger satisfies domain.Logger for tests.
type noopLogger struct{}

func (noopLogger) Info(msg string, args ...any)  {}
func (noopLogger) Warn(msg string, args ...any)  {}
func (noopLogger) Error(msg string, args ...any) {}
func (noopLogger) Debug(msg string, args ...any) {}

// genSafeName generates non-empty lowercase alphanumeric strings.
var genSafeName = gen.RegexMatch(`[a-z][a-z0-9]{1,8}`)

// ---------------------------------------------------------------------------
// Property 8: Read-only groups are denied write/delete tools
//
// For any tool name whose action segment starts with a write or delete prefix,
// a caller whose only group is "read-only" MUST receive Permitted == false.
//
// Validates: Requirements 3.3
// ---------------------------------------------------------------------------

func TestProperty8_ReadOnlyGroupDeniedWriteDeleteTools(t *testing.T) {
	policies := []domain.PolicyEntry{
		{
			Group: "read-only",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/get-*", "github/list-*"},
				DeniedTools:  []string{"github/delete-*", "github/create-*", "github/update-*"},
			},
		},
	}
	adapter := newAdapter(t, policies)
	ctx := context.Background()

	readOnlyIdentity := domain.IdentityContext{
		UserID: "alice",
		Groups: []string{"read-only"},
	}

	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 8a: write-prefixed tools are denied for read-only group
	writePrefixes := []string{"create-", "update-", "put-", "patch-"}
	properties.Property("write-prefixed tools denied for read-only group", prop.ForAll(
		func(action string) bool {
			for _, pfx := range writePrefixes {
				call := toolCall("github/" + pfx + action)
				decision, err := adapter.Evaluate(ctx, readOnlyIdentity, call)
				if err != nil {
					return false
				}
				if decision.Permitted {
					return false
				}
			}
			return true
		},
		genSafeName,
	))

	// 8b: delete-prefixed tools are denied for read-only group
	properties.Property("delete-prefixed tools denied for read-only group", prop.ForAll(
		func(action string) bool {
			call := toolCall("github/delete-" + action)
			decision, err := adapter.Evaluate(ctx, readOnlyIdentity, call)
			if err != nil {
				return false
			}
			return !decision.Permitted
		},
		genSafeName,
	))

	// 8c: read-prefixed tools are permitted for read-only group
	properties.Property("get-prefixed tools permitted for read-only group", prop.ForAll(
		func(action string) bool {
			call := toolCall("github/get-" + action)
			decision, err := adapter.Evaluate(ctx, readOnlyIdentity, call)
			if err != nil {
				return false
			}
			return decision.Permitted
		},
		genSafeName,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 9: Deny decisions always produce -32004 and no backend forwarding
//
// When OPAPolicyAdapter.Evaluate returns Permitted == false, the decision MUST
// carry a non-empty DenialReason. The Broker layer maps this to -32004; we
// verify the adapter side of the contract here.
//
// Validates: Requirements 3.4, 4.4
// ---------------------------------------------------------------------------

func TestProperty9_DenyDecisionsCarryDenialReason(t *testing.T) {
	policies := []domain.PolicyEntry{
		{
			Group: "developers",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/*"},
			},
		},
	}
	adapter := newAdapter(t, policies)
	ctx := context.Background()

	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 9a: caller with no matching group → denied with non-empty reason
	properties.Property("caller with no matching group gets non-empty denial reason", prop.ForAll(
		func(prefix, action string) bool {
			identity := domain.IdentityContext{
				UserID: "stranger",
				Groups: []string{"unknown-group"},
			}
			call := toolCall(prefix + "/" + action)
			decision, err := adapter.Evaluate(ctx, identity, call)
			if err != nil {
				return false
			}
			return !decision.Permitted && decision.DenialReason != ""
		},
		genSafeName, genSafeName,
	))

	// 9b: empty groups → denied with non-empty reason
	properties.Property("empty groups always denied with non-empty reason", prop.ForAll(
		func(prefix, action string) bool {
			identity := domain.IdentityContext{
				UserID: "nobody",
				Groups: []string{},
			}
			call := toolCall(prefix + "/" + action)
			decision, err := adapter.Evaluate(ctx, identity, call)
			if err != nil {
				return false
			}
			return !decision.Permitted && decision.DenialReason != ""
		},
		genSafeName, genSafeName,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 10: Unknown operation type defaults to deny
//
// When a tool name has no recognisable operation prefix (not get-, list-,
// create-, delete-, etc.), inferOperation returns "" and the Rego policy
// applies deny-by-default for unknown operation types.
//
// Validates: Requirements 3.7
// ---------------------------------------------------------------------------

func TestProperty10_UnknownOperationTypeDefaultsDeny(t *testing.T) {
	// Policy that would allow "github/*" for developers — but the tool name
	// has no recognisable operation prefix, so operation == "".
	policies := []domain.PolicyEntry{
		{
			Group: "developers",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/*"},
			},
		},
	}
	adapter := newAdapter(t, policies)
	ctx := context.Background()

	identity := domain.IdentityContext{
		UserID: "dev1",
		Groups: []string{"developers"},
	}

	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 10a: tool names with no operation prefix → operation == "" → deny-by-default
	// We use names that don't start with any known prefix.
	unknownPrefixes := []string{"run-", "exec-", "invoke-", "trigger-", "process-"}
	properties.Property("tool names with unknown operation prefix are denied", prop.ForAll(
		func(action string) bool {
			for _, pfx := range unknownPrefixes {
				call := toolCall("github/" + pfx + action)
				decision, err := adapter.Evaluate(ctx, identity, call)
				if err != nil {
					return false
				}
				// Unknown operation → deny-by-default per Requirement 3.7
				if decision.Permitted {
					return false
				}
			}
			return true
		},
		genSafeName,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 11: Policy decisions always carry a rule identifier
//
// Every PolicyDecision returned by OPAPolicyAdapter.Evaluate MUST have a
// non-empty MatchedRuleID — either the matched allow rule or a denial reason
// that identifies the rule that fired.
//
// Validates: Requirements 3.8
// ---------------------------------------------------------------------------

func TestProperty11_PolicyDecisionsAlwaysCarryRuleIdentifier(t *testing.T) {
	policies := []domain.PolicyEntry{
		{
			Group: "developers",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/*"},
			},
		},
		{
			Group: "read-only",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/get-*"},
				DeniedTools:  []string{"github/delete-*"},
			},
		},
	}
	adapter := newAdapter(t, policies)
	ctx := context.Background()

	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 11a: permitted decisions carry a non-empty MatchedRuleID
	properties.Property("permitted decisions carry non-empty MatchedRuleID", prop.ForAll(
		func(action string) bool {
			identity := domain.IdentityContext{
				UserID: "dev1",
				Groups: []string{"developers"},
			}
			call := toolCall("github/get-" + action)
			decision, err := adapter.Evaluate(ctx, identity, call)
			if err != nil {
				return false
			}
			if !decision.Permitted {
				return true // skip denied cases in this sub-property
			}
			return decision.MatchedRuleID != ""
		},
		genSafeName,
	))

	// 11b: denied decisions carry a non-empty DenialReason (the denial rule identifier)
	properties.Property("denied decisions carry non-empty DenialReason", prop.ForAll(
		func(action string) bool {
			identity := domain.IdentityContext{
				UserID: "nobody",
				Groups: []string{"unknown-group"},
			}
			call := toolCall("github/get-" + action)
			decision, err := adapter.Evaluate(ctx, identity, call)
			if err != nil {
				return false
			}
			return !decision.Permitted && decision.DenialReason != ""
		},
		genSafeName,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 12: Discovery result is always a subset of the full tool list
//
// FilterTools MUST return a slice that is a subset of the input toolNames.
// No tool may appear in the result that was not in the input.
// The result length MUST be ≤ len(toolNames).
//
// Validates: Requirements 4.1
// ---------------------------------------------------------------------------

func TestProperty12_DiscoveryResultIsSubsetOfFullToolList(t *testing.T) {
	policies := []domain.PolicyEntry{
		{
			Group: "developers",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/*"},
			},
		},
		{
			Group: "read-only",
			ReducedScope: domain.ReducedScope{
				AllowedTools: []string{"github/get-*", "github/list-*"},
				DeniedTools:  []string{"github/delete-*"},
			},
		},
	}
	adapter := newAdapter(t, policies)
	ctx := context.Background()

	// genToolList generates a slice of 1–10 tool names.
	genToolList := gen.SliceOfN(10, genSafeName).
		Map(func(names []string) []string {
			tools := make([]string, len(names))
			for i, n := range names {
				tools[i] = "github/get-" + n
			}
			return tools
		})

	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 12a: result is always a subset of input
	properties.Property("FilterTools result is always a subset of input", prop.ForAll(
		func(toolNames []string) bool {
			identity := domain.IdentityContext{
				UserID: "dev1",
				Groups: []string{"developers"},
			}
			result, err := adapter.FilterTools(ctx, identity, toolNames)
			if err != nil {
				return false
			}
			// Every result item must appear in the input.
			inputSet := make(map[string]struct{}, len(toolNames))
			for _, n := range toolNames {
				inputSet[n] = struct{}{}
			}
			for _, r := range result {
				if _, ok := inputSet[r]; !ok {
					return false
				}
			}
			return len(result) <= len(toolNames)
		},
		genToolList,
	))

	// 12b: read-only group gets a smaller or equal subset than developers
	properties.Property("read-only group gets subset of developer tools", prop.ForAll(
		func(action string) bool {
			allTools := []string{
				"github/get-" + action,
				"github/list-" + action,
				"github/create-" + action,
				"github/delete-" + action,
			}

			devIdentity := domain.IdentityContext{UserID: "dev1", Groups: []string{"developers"}}
			roIdentity := domain.IdentityContext{UserID: "ro1", Groups: []string{"read-only"}}

			devTools, err := adapter.FilterTools(ctx, devIdentity, allTools)
			if err != nil {
				return false
			}
			roTools, err := adapter.FilterTools(ctx, roIdentity, allTools)
			if err != nil {
				return false
			}

			// read-only result must be a subset of developer result
			devSet := make(map[string]struct{}, len(devTools))
			for _, t := range devTools {
				devSet[t] = struct{}{}
			}
			for _, t := range roTools {
				if _, ok := devSet[t]; !ok {
					return false
				}
			}
			return len(roTools) <= len(devTools)
		},
		genSafeName,
	))

	// 12c: empty groups → empty result
	properties.Property("empty groups always produce empty FilterTools result", prop.ForAll(
		func(action string) bool {
			allTools := []string{"github/get-" + action, "github/list-" + action}
			identity := domain.IdentityContext{UserID: "nobody", Groups: []string{}}
			result, err := adapter.FilterTools(ctx, identity, allTools)
			if err != nil {
				return false
			}
			return len(result) == 0
		},
		genSafeName,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
