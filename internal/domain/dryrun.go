package domain

import (
	"encoding/json"
	"path"
	"strings"
)

// DryRun simulates a call_tool request from the given identity against the
// provided Config without making any network calls or producing side effects.
//
// Step 1 — Policy check: finds all PolicyEntry items whose Group appears in
// identity.Groups, checks denied_tools first (takes precedence), then checks
// allowed_tools using path.Match semantics.
//
// Step 2 — Routing check: extracts the prefix from the tool name (segment
// before the first "/") and looks it up in cfg.Routes.
//
// This function is intentionally pure — same inputs always produce the same
// output. It is safe to call from tests, CLI tooling, and CI pipelines.
func DryRun(cfg Config, identity IdentityContext, call ToolCall) DryRunResult {
	toolName := toolNameFromCall(call)

	callerGroups := make(map[string]struct{}, len(identity.Groups))
	for _, g := range identity.Groups {
		callerGroups[g] = struct{}{}
	}

	var matchedPolicy string
	policyPermitted := false

	for _, entry := range cfg.Policies {
		if _, ok := callerGroups[entry.Group]; !ok {
			continue
		}
		// denied_tools takes precedence over allowed_tools
		if matchesAny(toolName, entry.ReducedScope.DeniedTools) {
			continue
		}
		if pattern, ok := firstMatch(toolName, entry.ReducedScope.AllowedTools); ok {
			matchedPolicy = entry.Group + " -> " + pattern
			policyPermitted = true
			break
		}
	}

	if !policyPermitted {
		return DryRunResult{
			Permitted:    false,
			DenialReason: "no policy permits tool \"" + toolName + "\" for the caller's groups",
		}
	}

	// Step 2: routing check
	prefix := toolPrefix(toolName)
	for _, route := range cfg.Routes {
		if route.Prefix == prefix {
			return DryRunResult{
				Permitted:     true,
				MatchedPolicy: matchedPolicy,
				MatchedRoute:  route.BackendURI,
			}
		}
	}

	return DryRunResult{
		Permitted:     false,
		MatchedPolicy: matchedPolicy,
		DenialReason:  "no route configured for tool prefix \"" + prefix + "\"",
	}
}

// toolNameFromCall extracts the tool name string from a ToolCall's Params field.
// MCP call_tool params have the shape: {"name": "<tool>", "arguments": {...}}.
// Returns an empty string if the params cannot be parsed.
func toolNameFromCall(call ToolCall) string {
	if len(call.Params) == 0 {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(call.Params, &p); err != nil {
		return ""
	}
	return p.Name
}

// toolPrefix returns the segment before the first "/" in a tool name.
// If there is no "/", the entire name is the prefix.
func toolPrefix(toolName string) string {
	if i := strings.Index(toolName, "/"); i >= 0 {
		return toolName[:i]
	}
	return toolName
}

// matchesAny reports whether toolName matches any pattern in the list.
func matchesAny(toolName string, patterns []string) bool {
	for _, p := range patterns {
		if matched, _ := path.Match(p, toolName); matched {
			return true
		}
	}
	return false
}

// firstMatch returns the first pattern in the list that matches toolName.
func firstMatch(toolName string, patterns []string) (string, bool) {
	for _, p := range patterns {
		if matched, _ := path.Match(p, toolName); matched {
			return p, true
		}
	}
	return "", false
}
