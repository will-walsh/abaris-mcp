// Package policy provides the OPA-backed PolicyEngine implementation for Abaris.
// It loads a Rego bundle from a local directory, prepares a query at startup,
// and evaluates it on every Evaluate/FilterTools call.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/metrics"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// Compile-time interface satisfaction check (task 5.5).
var _ domain.PolicyEngine = (*OPAPolicyAdapter)(nil)

// OPAPolicyAdapter implements domain.PolicyEngine using the OPA Go SDK.
// It loads a Rego bundle from bundlePath at startup, prepares the
// data.abaris.authz.allow query, and evaluates it on every call.
// Hot-reload is supported via StartHotReload (task 5.4).
type OPAPolicyAdapter struct {
	bundlePath string
	logger     domain.Logger

	mu       sync.RWMutex
	query    rego.PreparedEvalQuery
	policies []domain.PolicyEntry // kept for hot-reload
}

// opaInput is the JSON-serialisable input document sent to OPA on each evaluation.
type opaInput struct {
	Groups       []string `json:"groups"`
	Entitlements []string `json:"entitlements"`
	ToolName     string   `json:"tool_name"`
	Operation    string   `json:"operation"`
	AllowedTools []string `json:"allowed_tools"`
	DeniedTools  []string `json:"denied_tools"`
}

// New creates an OPAPolicyAdapter, loads the bundle from bundlePath, and
// prepares the evaluation query. policies is the merged domain.Config.Policies
// slice used to populate data.policies in OPA.
func New(ctx context.Context, bundlePath string, policies []domain.PolicyEntry, logger domain.Logger) (*OPAPolicyAdapter, error) {
	a := &OPAPolicyAdapter{
		bundlePath: bundlePath,
		logger:     logger,
	}
	if err := a.load(ctx, bundlePath, policies); err != nil {
		return nil, fmt.Errorf("policy: load bundle: %w", err)
	}
	return a, nil
}

// load (re)loads the bundle and prepares the query. Called at startup and on hot-reload.
func (a *OPAPolicyAdapter) load(ctx context.Context, bundlePath string, policies []domain.PolicyEntry) error {
	// Build data.policies from the domain PolicyEntry slice.
	dataDoc := buildDataDoc(policies)

	// Use rego.LoadBundle (path-based) which handles compilation internally,
	// combined with rego.Data for the policies document.
	// rego.Data creates an inmem store from the map; rego.LoadBundle loads
	// the Rego files and activates them into a separate internal store.
	// We merge both by using rego.Load for the Rego files and rego.Store
	// for the data, with a write transaction to activate the bundle.

	// Create an in-memory store pre-populated with data.policies.
	store := inmem.NewFromObject(dataDoc)

	// Open a write transaction to activate the bundle into the store.
	txn, err := store.NewTransaction(ctx, storage.WriteParams)
	if err != nil {
		return fmt.Errorf("open store transaction: %w", err)
	}

	// Load and compile the bundle from the directory.
	b, err := bundle.NewCustomReader(bundle.NewDirectoryLoader(bundlePath)).Read()
	if err != nil {
		store.Abort(ctx, txn)
		return fmt.Errorf("read bundle at %q: %w", bundlePath, err)
	}

	// Create a fresh compiler — bundle.Activate will compile the modules.
	compiler := ast.NewCompiler()

	if err := bundle.Activate(&bundle.ActivateOpts{
		Ctx:      ctx,
		Store:    store,
		Txn:      txn,
		Compiler: compiler,
		Metrics:  metrics.New(),
		Bundles:  map[string]*bundle.Bundle{"abaris": &b},
	}); err != nil {
		store.Abort(ctx, txn)
		return fmt.Errorf("activate bundle: %w", err)
	}

	if err := store.Commit(ctx, txn); err != nil {
		return fmt.Errorf("commit bundle activation: %w", err)
	}

	// Prepare the combined allow + matched_rule + deny_reason query.
	readTxn, err := store.NewTransaction(ctx)
	if err != nil {
		return fmt.Errorf("open read transaction: %w", err)
	}
	defer store.Abort(ctx, readTxn)

	pq, err := rego.New(
		rego.Query(`
			allow         = data.abaris.authz.allow;
			matched_rule  = data.abaris.authz.matched_rule;
			deny_reason   = data.abaris.authz.deny_reason
		`),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.Transaction(readTxn),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("prepare query: %w", err)
	}

	a.mu.Lock()
	a.query = pq
	a.policies = policies
	a.mu.Unlock()
	return nil
}

// Evaluate implements domain.PolicyEngine.
func (a *OPAPolicyAdapter) Evaluate(ctx context.Context, identity domain.IdentityContext, call domain.ToolCall) (domain.PolicyDecision, error) {
	toolName, operation := toolNameAndOperation(call)

	a.mu.RLock()
	policies := a.policies
	a.mu.RUnlock()

	allowed, denied := scopeForGroups(policies, identity.Groups)

	input := opaInput{
		Groups:       identity.Groups,
		Entitlements: identity.Entitlements,
		ToolName:     toolName,
		Operation:    operation,
		AllowedTools: allowed,
		DeniedTools:  denied,
	}

	a.logger.Debug("policy: evaluating",
		"tool", toolName,
		"operation", operation,
		"groups", identity.Groups,
		"allowed_patterns", allowed,
		"denied_patterns", denied,
	)

	rs, err := a.evalQuery(ctx, input)
	if err != nil {
		return domain.PolicyDecision{}, fmt.Errorf("%w: %s", domain.ErrServiceUnavailable, err)
	}

	decision := decisionFromResultSet(rs)
	a.logger.Debug("policy: decision",
		"tool", toolName,
		"permitted", decision.Permitted,
		"matched_rule", decision.MatchedRuleID,
		"denial_reason", decision.DenialReason,
	)
	return decision, nil
}

// FilterTools implements domain.PolicyEngine — returns the subset of toolNames
// permitted for the given identity (used by the Discovery / list_tools flow).
func (a *OPAPolicyAdapter) FilterTools(ctx context.Context, identity domain.IdentityContext, toolNames []string) ([]string, error) {
	a.logger.Debug("policy: FilterTools called", "user_id", identity.UserID, "groups", identity.Groups, "tool_count", len(toolNames))
	permitted := make([]string, 0, len(toolNames))
	for _, name := range toolNames {
		call := domain.ToolCall{
			JSONRPC: "2.0",
			Method:  "tools/call",
			Params:  json.RawMessage(fmt.Sprintf(`{"name":%q}`, name)),
		}
		decision, err := a.Evaluate(ctx, identity, call)
		if err != nil {
			return nil, err
		}
		if decision.Permitted {
			permitted = append(permitted, name)
		} else {
			a.logger.Debug("policy: tool denied", "tool", name, "reason", decision.DenialReason)
		}
	}
	a.logger.Debug("policy: FilterTools complete", "user_id", identity.UserID, "permitted_count", len(permitted))
	return permitted, nil
}

// StartHotReload polls bundlePath every interval, reloading the bundle and
// atomically swapping the PreparedEvalQuery on success. On failure it logs a
// warning and retains the previous query. Blocks until ctx is cancelled.
func (a *OPAPolicyAdapter) StartHotReload(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.mu.RLock()
			policies := a.policies
			a.mu.RUnlock()

			if err := a.load(ctx, a.bundlePath, policies); err != nil {
				a.logger.Warn("policy: hot-reload failed, retaining previous bundle", "error", err)
			} else {
				a.logger.Info("policy: hot-reload succeeded")
			}
		}
	}
}

// UpdatePolicies atomically replaces the data.policies document and re-prepares
// the query. Called by config.Loader after a successful hot-reload of policies/.
func (a *OPAPolicyAdapter) UpdatePolicies(ctx context.Context, policies []domain.PolicyEntry) error {
	return a.load(ctx, a.bundlePath, policies)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (a *OPAPolicyAdapter) evalQuery(ctx context.Context, input opaInput) (rego.ResultSet, error) {
	a.mu.RLock()
	pq := a.query
	a.mu.RUnlock()

	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}
	return rs, nil
}

func decisionFromResultSet(rs rego.ResultSet) domain.PolicyDecision {
	if len(rs) == 0 || len(rs[0].Bindings) == 0 {
		return domain.PolicyDecision{
			Permitted:    false,
			DenialReason: "no policy decision produced",
		}
	}

	bindings := rs[0].Bindings

	allowed, _ := bindings["allow"].(bool)
	matchedRule, _ := bindings["matched_rule"].(string)
	denyReason, _ := bindings["deny_reason"].(string)

	if allowed {
		return domain.PolicyDecision{
			Permitted:     true,
			MatchedRuleID: matchedRule,
		}
	}
	return domain.PolicyDecision{
		Permitted:     false,
		MatchedRuleID: matchedRule,
		DenialReason:  denyReason,
	}
}

// buildDataDoc converts domain.PolicyEntry slice into the map[string]any
// shape that OPA expects as data.policies.
func buildDataDoc(policies []domain.PolicyEntry) map[string]any {
	policyList := make([]any, 0, len(policies))
	for _, p := range policies {
		dt := p.ReducedScope.DeniedTools
		if dt == nil {
			dt = []string{}
		}
		policyList = append(policyList, map[string]any{
			"group": p.Group,
			"reduced_scope": map[string]any{
				"allowed_tools": p.ReducedScope.AllowedTools,
				"denied_tools":  dt,
			},
		})
	}
	return map[string]any{
		"policies": policyList,
	}
}

// scopeForGroups returns the union of allowed/denied tool patterns for the
// caller's groups from the domain.PolicyEntry slice.
func scopeForGroups(policies []domain.PolicyEntry, groups []string) (allowed, denied []string) {
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		groupSet[g] = struct{}{}
	}

	allowedSet := map[string]struct{}{}
	deniedSet := map[string]struct{}{}

	for _, p := range policies {
		if _, ok := groupSet[p.Group]; !ok {
			continue
		}
		for _, t := range p.ReducedScope.AllowedTools {
			allowedSet[t] = struct{}{}
		}
		for _, t := range p.ReducedScope.DeniedTools {
			deniedSet[t] = struct{}{}
		}
	}

	for t := range allowedSet {
		allowed = append(allowed, t)
	}
	for t := range deniedSet {
		denied = append(denied, t)
	}
	return
}

// toolNameAndOperation extracts the tool name and infers the operation type
// from a ToolCall's Params JSON.
func toolNameAndOperation(call domain.ToolCall) (name, operation string) {
	if call.Params == nil {
		return "", ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(call.Params, &p); err != nil {
		return "", ""
	}
	name = p.Name
	operation = inferOperation(name)
	return
}

// inferOperation classifies a tool name as "read", "write", "delete", or "".
// Handles both hyphen-separated (get-file) and underscore-separated (get_file) conventions.
func inferOperation(toolName string) string {
	// Strip the backend prefix (e.g. "github/") before matching.
	short := toolName
	for i := 0; i < len(toolName); i++ {
		if toolName[i] == '/' {
			short = toolName[i+1:]
			break
		}
	}

	// Normalise underscores to hyphens so both naming conventions match.
	normalised := strings.ReplaceAll(short, "_", "-")

	readPrefixes := []string{"get-", "list-", "read-", "fetch-", "search-"}
	writePrefixes := []string{"create-", "update-", "put-", "post-", "patch-", "add-", "set-"}
	deletePrefixes := []string{"delete-", "remove-", "destroy-", "purge-"}

	for _, pfx := range readPrefixes {
		if strings.HasPrefix(normalised, pfx) {
			return "read"
		}
	}
	for _, pfx := range writePrefixes {
		if strings.HasPrefix(normalised, pfx) {
			return "write"
		}
	}
	for _, pfx := range deletePrefixes {
		if strings.HasPrefix(normalised, pfx) {
			return "delete"
		}
	}
	return ""
}
