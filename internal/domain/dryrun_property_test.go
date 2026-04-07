package domain_test

import (
	"encoding/json"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// toolCallWithName builds a ToolCall whose Params encode the given tool name.
func toolCallWithName(name string) domain.ToolCall {
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{}})
	return domain.ToolCall{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  params,
	}
}

// minimalConfig builds a Config with a single route and a single policy entry.
func minimalConfig(prefix, backendURI, group string, allowed, denied []string) domain.Config {
	return domain.Config{
		Routes: []domain.RouteEntry{
			{Prefix: prefix, BackendURI: backendURI},
		},
		Policies: []domain.PolicyEntry{
			{
				Group: group,
				ReducedScope: domain.ReducedScope{
					AllowedTools: allowed,
					DeniedTools:  denied,
				},
			},
		},
	}
}

// genSafeString generates non-empty lowercase alphanumeric strings suitable
// for use as tool name segments, group names, and prefixes.
var genSafeString = gen.RegexMatch(`[a-z][a-z0-9]{1,10}`)

// genToolName generates a two-segment tool name like "prefix/action".
var genToolName = gopter.CombineGens(genSafeString, genSafeString).
	Map(func(v []interface{}) string {
		return v[0].(string) + "/" + v[1].(string)
	})

// Property 19: DryRun policy check correctness
//
// When a caller's group is listed in a PolicyEntry whose allowed_tools glob
// matches the requested tool name (and denied_tools does not), DryRun MUST
// return Permitted == true with a non-empty MatchedPolicy.
// When the caller's group is absent from all PolicyEntry items, DryRun MUST
// return Permitted == false.
//
// Validates: Requirements 5.4
func TestProperty19_DryRunPolicyCheckCorrectness(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 19a: matching group + wildcard allow → permitted
	properties.Property("matching group with wildcard allow is permitted", prop.ForAll(
		func(prefix, action, group string) bool {
			toolName := prefix + "/" + action
			cfg := minimalConfig(prefix, "http://backend:8080", group, []string{prefix + "/*"}, nil)
			identity := domain.IdentityContext{UserID: "u1", Groups: []string{group}}
			result := domain.DryRun(cfg, identity, toolCallWithName(toolName))
			return result.Permitted && result.MatchedPolicy != ""
		},
		genSafeString, genSafeString, genSafeString,
	))

	// 19b: caller group absent from all policies → denied
	properties.Property("absent group is always denied", prop.ForAll(
		func(prefix, action, policyGroup, callerGroup string) bool {
			if policyGroup == callerGroup {
				return true // skip equal case
			}
			toolName := prefix + "/" + action
			cfg := minimalConfig(prefix, "http://backend:8080", policyGroup, []string{prefix + "/*"}, nil)
			identity := domain.IdentityContext{UserID: "u1", Groups: []string{callerGroup}}
			result := domain.DryRun(cfg, identity, toolCallWithName(toolName))
			return !result.Permitted
		},
		genSafeString, genSafeString, genSafeString, genSafeString,
	))

	// 19c: denied_tools takes precedence over allowed_tools
	properties.Property("denied_tools takes precedence over allowed_tools", prop.ForAll(
		func(prefix, action, group string) bool {
			toolName := prefix + "/" + action
			// both allow and deny match the same tool
			cfg := minimalConfig(prefix, "http://backend:8080", group,
				[]string{prefix + "/*"},  // allowed
				[]string{prefix + "/*"},  // denied — same pattern, should win
			)
			identity := domain.IdentityContext{UserID: "u1", Groups: []string{group}}
			result := domain.DryRun(cfg, identity, toolCallWithName(toolName))
			return !result.Permitted
		},
		genSafeString, genSafeString, genSafeString,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Property 20: DryRun routing check correctness
//
// When the policy check passes, DryRun MUST resolve the BackendURI from the
// route whose Prefix matches the tool name's leading segment.
// When no route prefix matches, DryRun MUST return Permitted == false even if
// the policy check passed.
//
// Validates: Requirements 4.5, 4.6
func TestProperty20_DryRunRoutingCheckCorrectness(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 20a: matching route → MatchedRoute equals configured BackendURI
	properties.Property("matching route resolves correct BackendURI", prop.ForAll(
		func(prefix, action, group string) bool {
			toolName := prefix + "/" + action
			backendURI := "http://" + prefix + "-backend:8080"
			cfg := minimalConfig(prefix, backendURI, group, []string{prefix + "/*"}, nil)
			identity := domain.IdentityContext{UserID: "u1", Groups: []string{group}}
			result := domain.DryRun(cfg, identity, toolCallWithName(toolName))
			return result.Permitted && result.MatchedRoute == backendURI
		},
		genSafeString, genSafeString, genSafeString,
	))

	// 20b: no matching route → denied even when policy permits
	properties.Property("missing route denies even when policy permits", prop.ForAll(
		func(prefix, action, routePrefix, group string) bool {
			if prefix == routePrefix {
				return true // skip matching case
			}
			toolName := prefix + "/" + action
			// route is for a different prefix
			cfg := domain.Config{
				Routes: []domain.RouteEntry{
					{Prefix: routePrefix, BackendURI: "http://other:8080"},
				},
				Policies: []domain.PolicyEntry{
					{
						Group:        group,
						ReducedScope: domain.ReducedScope{AllowedTools: []string{prefix + "/*"}},
					},
				},
			}
			identity := domain.IdentityContext{UserID: "u1", Groups: []string{group}}
			result := domain.DryRun(cfg, identity, toolCallWithName(toolName))
			return !result.Permitted && result.DenialReason != ""
		},
		genSafeString, genSafeString, genSafeString, genSafeString,
	))

	// 20c: tool prefix extraction — single-segment tool name uses full name as prefix
	properties.Property("single-segment tool name uses full name as prefix", prop.ForAll(
		func(name, group string) bool {
			backendURI := "http://" + name + ":8080"
			cfg := domain.Config{
				Routes: []domain.RouteEntry{
					{Prefix: name, BackendURI: backendURI},
				},
				Policies: []domain.PolicyEntry{
					{
						Group:        group,
						ReducedScope: domain.ReducedScope{AllowedTools: []string{name}},
					},
				},
			}
			identity := domain.IdentityContext{UserID: "u1", Groups: []string{group}}
			result := domain.DryRun(cfg, identity, toolCallWithName(name))
			return result.Permitted && result.MatchedRoute == backendURI
		},
		genSafeString, genSafeString,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Property 21: DryRun determinism
//
// DryRun is a pure function: calling it twice with identical inputs MUST
// produce identical outputs. No mutable state, no randomness, no side effects.
//
// Validates: Requirements 5.7 (round-trip / determinism)
func TestProperty21_DryRunDeterminism(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("identical inputs always produce identical outputs", prop.ForAll(
		func(prefix, action, group string) bool {
			toolName := prefix + "/" + action
			cfg := minimalConfig(prefix, "http://backend:8080", group, []string{prefix + "/*"}, nil)
			identity := domain.IdentityContext{UserID: "u1", Groups: []string{group}}
			call := toolCallWithName(toolName)

			r1 := domain.DryRun(cfg, identity, call)
			r2 := domain.DryRun(cfg, identity, call)

			return r1.Permitted == r2.Permitted &&
				r1.MatchedPolicy == r2.MatchedPolicy &&
				r1.MatchedRoute == r2.MatchedRoute &&
				r1.DenialReason == r2.DenialReason
		},
		genSafeString, genSafeString, genSafeString,
	))

	// determinism also holds for denied cases
	properties.Property("denied results are also deterministic", prop.ForAll(
		func(prefix, action, policyGroup, callerGroup string) bool {
			if policyGroup == callerGroup {
				return true
			}
			toolName := prefix + "/" + action
			cfg := minimalConfig(prefix, "http://backend:8080", policyGroup, []string{prefix + "/*"}, nil)
			identity := domain.IdentityContext{UserID: "u1", Groups: []string{callerGroup}}
			call := toolCallWithName(toolName)

			r1 := domain.DryRun(cfg, identity, call)
			r2 := domain.DryRun(cfg, identity, call)

			return r1.Permitted == r2.Permitted &&
				r1.DenialReason == r2.DenialReason
		},
		genSafeString, genSafeString, genSafeString, genSafeString,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}
