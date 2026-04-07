package abaris.authz

import rego.v1

# ---------------------------------------------------------------------------
# Default decisions
# ---------------------------------------------------------------------------

# Default deny — every tool call is denied unless an explicit allow rule fires.
default allow := false

# Default deny_reason — overridden by specific rules below.
default deny_reason := "no policy permits this tool call for the caller's groups"

# Default matched_rule — overridden when a rule fires.
default matched_rule := ""

# ---------------------------------------------------------------------------
# Input shape (expected by Abaris Broker):
#
#   input.groups        []string  — caller's normalized IdentityContext.Groups
#   input.entitlements  []string  — caller's normalized IdentityContext.Entitlements
#   input.tool_name     string    — e.g. "github/create-pr"
#   input.operation     string    — "read" | "write" | "delete" | "" (unknown)
#   input.allowed_tools []string  — glob patterns from the merged PolicyEntry
#   input.denied_tools  []string  — glob patterns from the merged PolicyEntry
#
# data shape (loaded from OPA bundle data.json):
#
#   data.policies  []{ group, reduced_scope: { allowed_tools, denied_tools } }
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Known operation types — deny-by-default for unknown (Requirement 3.7)
# ---------------------------------------------------------------------------

known_operations := {"read", "write", "delete"}

operation_known if {
	known_operations[input.operation]
}

# ---------------------------------------------------------------------------
# Helper: glob matching using OPA's glob.match with "/" as delimiter.
# ---------------------------------------------------------------------------

glob_match(pattern, name) if {
	glob.match(pattern, ["/"], name)
}

# ---------------------------------------------------------------------------
# Group membership set — built from input.groups for O(1) lookup.
# ---------------------------------------------------------------------------

caller_groups := {g | g := input.groups[_]}

# ---------------------------------------------------------------------------
# Deny-list check — true when the tool is explicitly denied by any policy
# whose group the caller belongs to.
# ---------------------------------------------------------------------------

tool_denied if {
	some i
	entry := data.policies[i]
	caller_groups[entry.group]
	some j
	pattern := entry.reduced_scope.denied_tools[j]
	glob_match(pattern, input.tool_name)
}

# ---------------------------------------------------------------------------
# Allow rule — group-based allow
#
# Fires when:
#   1. The operation type is known (deny-by-default for unknown — Req 3.7).
#   2. The caller belongs to a group that has a matching policy.
#   3. The tool name matches an allowed_tools pattern in that policy.
#   4. The tool is NOT in the denied_tools list of any applicable policy.
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# matched_rule — identifies which group + pattern permitted the call.
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# deny_reason — specific denial messages
# ---------------------------------------------------------------------------

# Unknown operation type — deny by default (Requirement 3.7)
deny_reason := "unauthorized: unknown operation type; deny-by-default applied" if {
	not allow
	not operation_known
}

# Read-only group: deny write/delete operations (Requirement 3.3)
deny_reason := "unauthorized: read-only group cannot perform write or delete operations" if {
	not allow
	operation_known
	caller_groups["read-only"]
	input.operation != "read"
}

# No matching policy for the caller's groups
deny_reason := "unauthorized: no policy permits this tool call for the caller's groups" if {
	not allow
	operation_known
	not caller_groups["read-only"]
}
