package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// OBOPipeline is the interface for the On-Behalf-Of pipeline (Phase 11).
// The Broker delegates call_tool to this when RouteEntry.OBOProvider is set.
// Defined here as an interface so Phase 6 compiles without Phase 11 code.
type OBOPipeline interface {
	Execute(ctx context.Context, call domain.ToolCall, route domain.RouteEntry) ([]byte, error)
}

// CredentialStore retrieves service credentials for a given backend prefix.
// The production implementation fetches from AWS Secrets Manager.
type CredentialStore interface {
	// GetServiceCredential returns the service credential (e.g. API key or
	// Bearer token) for the backend identified by prefix.
	GetServiceCredential(ctx context.Context, prefix string) (string, error)
}

// Broker is the MCP Proxy_Core. It orchestrates identity resolution, policy
// evaluation, Discovery filtering, and Execution routing.
//
// Broker depends only on domain interfaces — no infrastructure imports.
// All concrete adapters are wired at the composition root.
type Broker struct {
	identity     domain.IdentityService
	policy       domain.PolicyEngine
	transport    domain.BackendTransport    // default HTTP transport
	sseTransport domain.BackendTransport    // SSE transport for routes with transport: sse
	minter       domain.IdentityAssertionMinter
	creds        CredentialStore
	logger       domain.Logger
	routes       []domain.RouteEntry
	store        domain.TokenStore // optional; used for OBO route discovery

	// obo is optional; set when Phase 11 OBO pipeline is wired.
	// When nil, any route with OBOProvider set returns ErrServiceUnavailable.
	obo OBOPipeline
}

// BrokerConfig holds the dependencies for constructing a Broker.
type BrokerConfig struct {
	Identity     domain.IdentityService
	Policy       domain.PolicyEngine
	Transport    domain.BackendTransport // default HTTP transport
	SSETransport domain.BackendTransport // optional SSE transport; created automatically if nil
	Minter       domain.IdentityAssertionMinter
	Creds        CredentialStore
	Logger       domain.Logger
	Routes       []domain.RouteEntry
	Store        domain.TokenStore // optional; used for OBO route discovery
	// OBO is optional; leave nil until Phase 11.
	OBO OBOPipeline
}

// NewBroker constructs a Broker from the provided config.
func NewBroker(cfg BrokerConfig) (*Broker, error) {
	if cfg.Identity == nil {
		return nil, fmt.Errorf("broker: IdentityService is required")
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("broker: PolicyEngine is required")
	}
	if cfg.Transport == nil {
		return nil, fmt.Errorf("broker: BackendTransport is required")
	}
	if cfg.Minter == nil {
		return nil, fmt.Errorf("broker: IdentityAssertionMinter is required")
	}
	if cfg.Creds == nil {
		return nil, fmt.Errorf("broker: CredentialStore is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("broker: Logger is required")
	}
	sseTransport := cfg.SSETransport
	if sseTransport == nil {
		sseTransport = NewSSEBackendTransport(nil, cfg.Logger)
	}
	return &Broker{
		identity:     cfg.Identity,
		policy:       cfg.Policy,
		transport:    cfg.Transport,
		sseTransport: sseTransport,
		minter:       cfg.Minter,
		creds:        cfg.Creds,
		logger:       cfg.Logger,
		routes:       cfg.Routes,
		store:        cfg.Store,
		obo:          cfg.OBO,
	}, nil
}

// UpdateRoutes atomically replaces the active route table.
// Called by config.Loader when routing.yaml changes (requires restart,
// but exposed here for testing and future use).
func (b *Broker) UpdateRoutes(routes []domain.RouteEntry) {
	b.routes = routes
}

// Handle is the single entry point for all inbound MCP requests.
// It parses the raw JSON-RPC 2.0 bytes, dispatches to Discovery or Execution,
// and returns the raw response bytes.
//
// transportType is a label for structured logging (e.g. "sse", "stdio").
func (b *Broker) Handle(ctx context.Context, data []byte, transportType string) []byte {
	// Attempt to extract the request ID for error responses even if parsing fails.
	var idHolder struct {
		ID any `json:"id"`
	}
	_ = json.Unmarshal(data, &idHolder)

	call, err := ParseToolCall(data)
	if err != nil {
		return ErrorResponse(idHolder.ID, domain.CodeInvalidRequest,
			"invalid request: does not conform to JSON-RPC 2.0")
	}

	switch call.Method {
	case "tools/list":
		return b.handleDiscovery(ctx, call, transportType)
	case "tools/call":
		return b.handleExecution(ctx, call, transportType)
	default:
		// Unknown method — treat as invalid request per MCP spec.
		return ErrorResponse(call.ID, domain.CodeInvalidRequest,
			fmt.Sprintf("unknown method %q", call.Method))
	}
}

// ---------------------------------------------------------------------------
// Discovery flow (list_tools / tools/list)
// ---------------------------------------------------------------------------

// handleDiscovery implements the Discovery flow (Requirement 4.1):
// aggregate tool lists from all backends, filter by identity via OPA,
// return the reduced list.
func (b *Broker) handleDiscovery(ctx context.Context, call domain.ToolCall, transportType string) []byte {
	requestID := requestIDFromCall(call)

	// Resolve identity.
	identity, err := b.identity.Resolve(ctx)
	if err != nil {
		return b.identityErrorResponse(call.ID, requestID, err)
	}

	b.logToolCall(requestID, identity.UserID, "tools/list", transportType)

	// Aggregate tool lists from all backends using service credentials.
	allTools, err := b.aggregateTools(ctx)
	if err != nil {
		b.logger.Error("broker: discovery: aggregate tools failed",
			"request_id", requestID, "error", err)
		return ErrorResponse(call.ID, domain.CodeServiceUnavailable,
			"service unavailable: could not aggregate tool lists from backends")
	}

	// Filter by identity via OPA.
	permitted, err := b.policy.FilterTools(ctx, identity, allTools)
	if err != nil {
		b.logger.Error("broker: discovery: filter tools failed",
			"request_id", requestID, "user_id", identity.UserID, "error", err)
		return ErrorResponse(call.ID, domain.CodeServiceUnavailable,
			"service unavailable: policy engine error")
	}

	return SuccessResponse(call.ID, map[string]any{"tools": permitted})
}

// aggregateTools calls list_tools on every configured backend and returns
// the union of all tool names. Uses service credentials for each backend.
func (b *Broker) aggregateTools(ctx context.Context) ([]string, error) {
	var all []string
	seen := make(map[string]struct{})

	// Resolve identity once for OBO routes.
	var identity *domain.IdentityContext
	if b.store != nil {
		if id, err := b.identity.Resolve(ctx); err == nil {
			identity = &id
		}
	}

	for _, route := range b.routes {
		var credCtx context.Context

		if route.OBOProvider != "" && b.store != nil && identity != nil {
			// OBO route: use the user's UAT from the token store.
			pair, err := b.store.Get(ctx, identity.UserID, route.OBOProvider)
			if err != nil {
				b.logger.Warn("aggregateTools: skipping OBO backend, no UAT", "prefix", route.Prefix, "provider", route.OBOProvider)
				continue
			}
			credCtx = WithServiceCredential(ctx, pair.AccessToken)
		} else {
			// Standard route: use service credentials.
			cred, err := b.creds.GetServiceCredential(ctx, route.Prefix)
			if err != nil {
				b.logger.Warn("aggregateTools: skipping backend, no service credential", "prefix", route.Prefix, "error", err)
				continue
			}
			credCtx = WithServiceCredential(ctx, cred)
		}

		listCall := domain.ToolCall{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/list",
		}
		respBytes, err := b.transportFor(route).Forward(credCtx, route.BackendURI, listCall, "")
		if err != nil {
			b.logger.Warn("aggregateTools: skipping backend, forward failed", "backend", route.BackendURI, "error", err)
			continue
		}

		tools, err := parseToolListResponse(respBytes)
		if err != nil {
			b.logger.Warn("aggregateTools: skipping backend, parse failed", "backend", route.BackendURI, "error", err)
			continue
		}

		if len(tools) == 0 {
			b.logger.Warn("aggregateTools: backend returned zero tools", "backend", route.BackendURI, "response_preview", previewBytes(respBytes, 512))
		}

		for _, t := range tools {
			if _, dup := seen[t]; !dup {
				seen[t] = struct{}{}
				all = append(all, t)
			}
		}
	}
	return all, nil
}

// parseToolListResponse extracts the tool name list from a JSON-RPC 2.0
// tools/list response. Accepts both {"result":{"tools":[...]}} and
// {"result":[...]} shapes.
func parseToolListResponse(data []byte) ([]string, error) {
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *jsonRPCError   `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("backend error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		return nil, nil
	}

	// Try {"tools": [...]} shape first.
	var withTools struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &withTools); err == nil && withTools.Tools != nil {
		return extractToolNames(withTools.Tools), nil
	}

	// Try flat array shape.
	var flat []json.RawMessage
	if err := json.Unmarshal(resp.Result, &flat); err == nil {
		return extractToolNames(flat), nil
	}

	return nil, nil
}

// extractToolNames pulls the "name" field from each tool object in the list.
func extractToolNames(items []json.RawMessage) []string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		var t struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(item, &t); err == nil && t.Name != "" {
			names = append(names, t.Name)
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Execution flow (call_tool / tools/call)
// ---------------------------------------------------------------------------

// handleExecution implements the Execution flow (Requirements 4.2–4.10):
// resolve identity → evaluate policy → route to backend.
func (b *Broker) handleExecution(ctx context.Context, call domain.ToolCall, transportType string) []byte {
	requestID := requestIDFromCall(call)
	toolName := toolNameFromCall(call)

	// Resolve identity.
	identity, err := b.identity.Resolve(ctx)
	if err != nil {
		return b.identityErrorResponse(call.ID, requestID, err)
	}

	b.logToolCall(requestID, identity.UserID, toolName, transportType)

	// Evaluate policy.
	decision, err := b.policy.Evaluate(ctx, identity, call)
	if err != nil {
		b.logger.Error("broker: policy evaluation error",
			"request_id", requestID, "user_id", identity.UserID,
			"tool_name", toolName, "error", err)
		return ErrorResponse(call.ID, domain.CodeServiceUnavailable,
			"service unavailable: policy engine error")
	}

	b.logPolicyDecision(requestID, identity.UserID, toolName, decision)

	if !decision.Permitted {
		return ErrorResponse(call.ID, domain.CodePolicyDenied,
			"unauthorized: insufficient entitlements")
	}

	// Resolve route.
	route, err := b.resolveRoute(toolName)
	if err != nil {
		return ErrorResponse(call.ID, domain.CodeInvalidParams,
			fmt.Sprintf("invalid params: no route configured for tool prefix %q", toolPrefix(toolName)))
	}

	// Dispatch: OBO pipeline or standard service-credentials path.
	if route.OBOProvider != "" {
		return b.handleOBO(ctx, call, route)
	}
	return b.handleStandard(ctx, call, identity, route, requestID)
}

// handleStandard executes the standard (non-OBO) forwarding path:
// retrieve service credentials → mint Identity Assertion Token → forward.
// The caller's raw token is never forwarded (Requirement 4.5).
func (b *Broker) handleStandard(
	ctx context.Context,
	call domain.ToolCall,
	identity domain.IdentityContext,
	route domain.RouteEntry,
	requestID string,
) []byte {
	// Retrieve service credentials for this backend.
	cred, err := b.creds.GetServiceCredential(ctx, route.Prefix)
	if err != nil {
		b.logger.Error("broker: get service credential failed",
			"request_id", requestID, "prefix", route.Prefix, "error", err)
		return ErrorResponse(call.ID, domain.CodeServiceUnavailable,
			"service unavailable: could not retrieve service credentials")
	}

	// Extract originJTI from the inbound Bearer token (best-effort).
	bearerToken, _ := authctx.BearerTokenFromContext(ctx)
	originJTI := originJTIFromToken(bearerToken)

	// Mint Identity Assertion Token (Requirement 4.4).
	assertionToken, err := b.minter.Mint(ctx, identity, originJTI)
	if err != nil {
		b.logger.Error("broker: mint identity assertion token failed",
			"request_id", requestID, "user_id", identity.UserID, "error", err)
		return ErrorResponse(call.ID, domain.CodeServiceUnavailable,
			"service unavailable: could not mint identity assertion token")
	}

	// Inject service credential into context so the BackendTransport can use it.
	// The caller's raw Bearer token is NOT forwarded (Requirement 4.5).
	ctx = WithServiceCredential(ctx, cred)

	// Forward using the assertion token as the X-Abaris-Identity header value.
	// The BackendTransport retrieves the service credential from context.
	respBytes, err := b.transportFor(route).Forward(ctx, route.BackendURI, call, assertionToken)
	if err != nil {
		b.logger.Error("broker: backend forward failed",
			"request_id", requestID, "backend_uri", route.BackendURI, "error", err)
		return ErrorResponse(call.ID, domain.CodeServiceUnavailable,
			"service unavailable: backend unreachable")
	}

	return respBytes
}

// handleOBO delegates to the OBO pipeline when RouteEntry.OBOProvider is set.
func (b *Broker) handleOBO(ctx context.Context, call domain.ToolCall, route domain.RouteEntry) []byte {
	if b.obo == nil {
		return ErrorResponse(call.ID, domain.CodeServiceUnavailable,
			"service unavailable: OBO pipeline not configured")
	}
	respBytes, err := b.obo.Execute(ctx, call, route)
	if err != nil {
		return ErrorResponse(call.ID, domain.CodeServiceUnavailable,
			fmt.Sprintf("service unavailable: OBO pipeline error: %s", err))
	}
	return respBytes
}

// resolveRoute finds the RouteEntry whose Prefix matches the tool name's
// leading segment. Returns ErrNoRoute if no match is found.
func (b *Broker) resolveRoute(toolName string) (domain.RouteEntry, error) {
	prefix := toolPrefix(toolName)
	for _, r := range b.routes {
		if r.Prefix == prefix {
			return r, nil
		}
	}
	return domain.RouteEntry{}, fmt.Errorf("%w: %q", domain.ErrNoRoute, prefix)
}

// transportFor returns the appropriate BackendTransport for the given route.
// Routes with transport: "sse" use the SSE backend transport; all others use HTTP.
func (b *Broker) transportFor(route domain.RouteEntry) domain.BackendTransport {
	if route.Transport == "sse" {
		return b.sseTransport
	}
	return b.transport
}

// ---------------------------------------------------------------------------
// Structured logging helpers (Requirements 6.2, 6.3, 6.4)
// ---------------------------------------------------------------------------

// logToolCall emits a structured log entry for every received ToolCall.
// Fields: request_id, caller_user_id, tool_name, transport_type, timestamp.
func (b *Broker) logToolCall(requestID, userID, toolName, transportType string) {
	b.logger.Info("tool_call_received",
		"request_id", requestID,
		"caller_user_id", userID,
		"tool_name", toolName,
		"transport_type", transportType,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
	)
}

// logPolicyDecision emits a structured log entry for every policy decision.
// Fields: request_id, caller_user_id, tool_name, decision_outcome, matched_rule_id.
func (b *Broker) logPolicyDecision(requestID, userID, toolName string, decision domain.PolicyDecision) {
	outcome := "permit"
	if !decision.Permitted {
		outcome = "deny"
	}
	b.logger.Info("policy_decision",
		"request_id", requestID,
		"caller_user_id", userID,
		"tool_name", toolName,
		"decision_outcome", outcome,
		"matched_rule_id", decision.MatchedRuleID,
	)
}

// ---------------------------------------------------------------------------
// Error response helpers
// ---------------------------------------------------------------------------

// identityErrorResponse maps domain identity errors to JSON-RPC error codes.
func (b *Broker) identityErrorResponse(id any, requestID string, err error) []byte {
	switch {
	case errors.Is(err, domain.ErrUnauthenticated):
		b.logger.Info("broker: unauthenticated request",
			"request_id", requestID, "error_type", "unauthenticated")
		return ErrorResponse(id, domain.CodeUnauthenticated,
			"unauthenticated: no identity credential present")
	case errors.Is(err, domain.ErrServiceUnavailable):
		b.logger.Error("broker: identity provider unavailable",
			"request_id", requestID, "error_type", "service_unavailable")
		return ErrorResponse(id, domain.CodeServiceUnavailable,
			"service unavailable: identity provider unreachable")
	default:
		b.logger.Error("broker: identity resolution failed",
			"request_id", requestID, "error_type", "unauthorized")
		return ErrorResponse(id, domain.CodeUnauthorized,
			"unauthorized: invalid or expired credential")
	}
}

// requestIDFromCall returns the request ID as a string for logging.
// Uses the JSON-RPC ID if present, otherwise generates a UUID.
func requestIDFromCall(call domain.ToolCall) string {
	if call.ID != nil {
		return fmt.Sprintf("%v", call.ID)
	}
	return uuid.NewString()
}

// previewBytes returns up to n bytes of b as a string, safe for logging.
// Truncates at a valid UTF-8 boundary and appends "..." if truncated.
func previewBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	// Truncate at a valid UTF-8 boundary.
	s := b[:n]
	for !utf8.Valid(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return string(s) + "..."
}
