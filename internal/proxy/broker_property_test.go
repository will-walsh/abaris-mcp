package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/proxy"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// stubIdentityService always returns the configured identity or error.
type stubIdentityService struct {
	identity domain.IdentityContext
	err      error
}

func (s *stubIdentityService) Resolve(_ context.Context) (domain.IdentityContext, error) {
	return s.identity, s.err
}

// stubPolicyEngine always returns the configured decision or error.
type stubPolicyEngine struct {
	decision    domain.PolicyDecision
	err         error
	filterTools []string
	filterErr   error
	// recordedCalls captures (identity, call) pairs for inspection.
	recordedCalls []struct {
		Identity domain.IdentityContext
		Call     domain.ToolCall
	}
}

func (s *stubPolicyEngine) Evaluate(_ context.Context, identity domain.IdentityContext, call domain.ToolCall) (domain.PolicyDecision, error) {
	s.recordedCalls = append(s.recordedCalls, struct {
		Identity domain.IdentityContext
		Call     domain.ToolCall
	}{identity, call})
	return s.decision, s.err
}

func (s *stubPolicyEngine) FilterTools(_ context.Context, _ domain.IdentityContext, toolNames []string) ([]string, error) {
	if s.filterErr != nil {
		return nil, s.filterErr
	}
	if s.filterTools != nil {
		return s.filterTools, nil
	}
	return toolNames, nil
}

// recordingTransport records every Forward call and returns a configurable response.
type recordingTransport struct {
	response    []byte
	err         error
	forwardedTo []string
	// capturedHeaders stores the identityToken passed to each Forward call.
	capturedTokens []string
	// capturedCreds stores the service credential from context for each call.
	capturedCreds []string
}

func (t *recordingTransport) Forward(ctx context.Context, backendURL string, _ domain.ToolCall, identityToken string) ([]byte, error) {
	t.forwardedTo = append(t.forwardedTo, backendURL)
	t.capturedTokens = append(t.capturedTokens, identityToken)
	if cred, ok := proxy.ServiceCredentialFromContext(ctx); ok {
		t.capturedCreds = append(t.capturedCreds, cred)
	}
	if t.err != nil {
		return nil, t.err
	}
	if t.response != nil {
		return t.response, nil
	}
	// Default: return a valid JSON-RPC 2.0 success response.
	resp, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  map[string]any{},
	})
	return resp, nil
}

// stubMinter always returns the configured token or error.
type stubMinter struct {
	token string
	err   error
	// capturedOriginJTIs records the originJTI passed to each Mint call.
	capturedOriginJTIs []string
}

func (m *stubMinter) Mint(_ context.Context, _ domain.IdentityContext, originJTI string) (string, error) {
	m.capturedOriginJTIs = append(m.capturedOriginJTIs, originJTI)
	return m.token, m.err
}

// stubCredStore always returns the configured credential or error.
type stubCredStore struct {
	cred string
	err  error
}

func (s *stubCredStore) GetServiceCredential(_ context.Context, _ string) (string, error) {
	return s.cred, s.err
}

// capturingLogger records all log calls for inspection.
type capturingLogger struct {
	entries []logEntry
}

type logEntry struct {
	level string
	msg   string
	args  []any
}

func (l *capturingLogger) Info(msg string, args ...any) {
	l.entries = append(l.entries, logEntry{"info", msg, args})
}
func (l *capturingLogger) Warn(msg string, args ...any) {
	l.entries = append(l.entries, logEntry{"warn", msg, args})
}
func (l *capturingLogger) Error(msg string, args ...any) {
	l.entries = append(l.entries, logEntry{"error", msg, args})
}
func (l *capturingLogger) Debug(msg string, args ...any) {
	l.entries = append(l.entries, logEntry{"debug", msg, args})
}

// hasField returns true if any log entry contains the given key-value pair.
func (l *capturingLogger) hasField(key string, value any) bool {
	for _, e := range l.entries {
		for i := 0; i+1 < len(e.args); i += 2 {
			if fmt.Sprintf("%v", e.args[i]) == key &&
				fmt.Sprintf("%v", e.args[i+1]) == fmt.Sprintf("%v", value) {
				return true
			}
		}
	}
	return false
}

// hasFieldKey returns true if any log entry contains the given key (any value).
func (l *capturingLogger) hasFieldKey(key string) bool {
	for _, e := range l.entries {
		for i := 0; i+1 < len(e.args); i += 2 {
			if fmt.Sprintf("%v", e.args[i]) == key {
				return true
			}
		}
	}
	return false
}

// containsSensitiveValue returns true if any log entry contains the given
// sensitive string as a value.
func (l *capturingLogger) containsSensitiveValue(sensitive string) bool {
	if sensitive == "" {
		return false
	}
	for _, e := range l.entries {
		if strings.Contains(e.msg, sensitive) {
			return true
		}
		for _, arg := range e.args {
			if strings.Contains(fmt.Sprintf("%v", arg), sensitive) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var genSafeStr = gen.RegexMatch(`[a-z][a-z0-9]{1,10}`)

func toolCallJSON(method, toolName string, id any) []byte {
	params, _ := json.Marshal(map[string]any{"name": toolName, "arguments": map[string]any{}})
	call := domain.ToolCall{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}
	b, _ := json.Marshal(call)
	return b
}

func defaultBroker(
	identity *stubIdentityService,
	policy *stubPolicyEngine,
	transport *recordingTransport,
	minter *stubMinter,
	creds *stubCredStore,
	logger *capturingLogger,
	routes []domain.RouteEntry,
) *proxy.Broker {
	b, err := proxy.NewBroker(proxy.BrokerConfig{
		Identity:  identity,
		Policy:    policy,
		Transport: transport,
		Minter:    minter,
		Creds:     creds,
		Logger:    logger,
		Routes:    routes,
	})
	if err != nil {
		panic(fmt.Sprintf("defaultBroker: %v", err))
	}
	return b
}

func successBackendResponse(id any) []byte {
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  map[string]any{"content": "ok"},
	})
	return b
}

// ---------------------------------------------------------------------------
// Property 1: MCP request parsing round-trip
//
// For any valid JSON-RPC 2.0 request, ParseToolCall followed by JSON marshal
// produces a document that parses back to an equivalent ToolCall.
// Validates: Requirements 1.2, 1.3
// ---------------------------------------------------------------------------

func TestProperty1_MCPRequestParsingRoundTrip(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("valid JSON-RPC 2.0 round-trips through ParseToolCall", prop.ForAll(
		func(method, toolName string, id int) bool {
			original := domain.ToolCall{
				JSONRPC: "2.0",
				ID:      float64(id), // JSON numbers unmarshal as float64
				Method:  method,
				Params:  json.RawMessage(fmt.Sprintf(`{"name":%q}`, toolName)),
			}
			data, err := json.Marshal(original)
			if err != nil {
				return false
			}
			parsed, err := proxy.ParseToolCall(data)
			if err != nil {
				return false
			}
			// Method and JSONRPC must be preserved exactly.
			return parsed.Method == original.Method &&
				parsed.JSONRPC == original.JSONRPC &&
				parsed.Params != nil
		},
		genSafeStr,
		genSafeStr,
		gen.IntRange(1, 10000),
	))

	properties.Property("ParseToolCall preserves Params bytes", prop.ForAll(
		func(toolName string) bool {
			params := json.RawMessage(fmt.Sprintf(`{"name":%q,"arguments":{}}`, toolName))
			call := domain.ToolCall{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "tools/call",
				Params:  params,
			}
			data, _ := json.Marshal(call)
			parsed, err := proxy.ParseToolCall(data)
			if err != nil {
				return false
			}
			// Params must round-trip to equivalent JSON.
			var orig, got map[string]any
			_ = json.Unmarshal(params, &orig)
			_ = json.Unmarshal(parsed.Params, &got)
			return fmt.Sprintf("%v", orig["name"]) == fmt.Sprintf("%v", got["name"])
		},
		genSafeStr,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 2: Invalid requests always produce -32600
//
// For any input that is not valid JSON-RPC 2.0, the Broker MUST return a
// JSON-RPC 2.0 error response with code -32600.
// Validates: Requirements 1.5
// ---------------------------------------------------------------------------

func TestProperty2_InvalidRequestsAlwaysProduce32600(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	logger := &capturingLogger{}
	identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "u1", Groups: []string{"dev"}}}
	policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
	transport := &recordingTransport{}
	minter := &stubMinter{token: "signed-jwt"}
	creds := &stubCredStore{cred: "svc-cred"}
	routes := []domain.RouteEntry{{Prefix: "github", BackendURI: "http://backend:8080"}}
	broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

	// 2a: not JSON at all
	properties.Property("non-JSON input produces -32600", prop.ForAll(
		func(garbage string) bool {
			if json.Valid([]byte(garbage)) {
				return true // skip valid JSON
			}
			resp := broker.Handle(context.Background(), []byte(garbage), "test")
			return errorCodeFromResponse(resp) == domain.CodeInvalidRequest
		},
		gen.RegexMatch(`[^{}\[\]"]{5,20}`),
	))

	// 2b: valid JSON but missing jsonrpc field
	properties.Property("missing jsonrpc field produces -32600", prop.ForAll(
		func(method string) bool {
			data := []byte(fmt.Sprintf(`{"method":%q,"id":1}`, method))
			resp := broker.Handle(context.Background(), data, "test")
			return errorCodeFromResponse(resp) == domain.CodeInvalidRequest
		},
		genSafeStr,
	))

	// 2c: jsonrpc != "2.0"
	properties.Property("jsonrpc != 2.0 produces -32600", prop.ForAll(
		func(version, method string) bool {
			if version == "2.0" {
				return true
			}
			data := []byte(fmt.Sprintf(`{"jsonrpc":%q,"method":%q,"id":1}`, version, method))
			resp := broker.Handle(context.Background(), data, "test")
			return errorCodeFromResponse(resp) == domain.CodeInvalidRequest
		},
		gen.RegexMatch(`[0-9]\.[0-9]`),
		genSafeStr,
	))

	// 2d: empty method
	properties.Property("empty method produces -32600", prop.ForAll(
		func(_ string) bool {
			data := []byte(`{"jsonrpc":"2.0","method":"","id":1}`)
			resp := broker.Handle(context.Background(), data, "test")
			return errorCodeFromResponse(resp) == domain.CodeInvalidRequest
		},
		genSafeStr,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 3: Backend response pass-through identity
//
// When a tool call is permitted, the Broker MUST return the backend response
// unmodified (the bytes returned by BackendTransport.Forward are the response).
// Validates: Requirements 1.4
// ---------------------------------------------------------------------------

func TestProperty3_BackendResponsePassThrough(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("permitted call returns backend response unmodified", prop.ForAll(
		func(toolName string, id int) bool {
			backendResp := successBackendResponse(id)

			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "u1", Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
			transport := &recordingTransport{response: backendResp}
			minter := &stubMinter{token: "signed-jwt"}
			creds := &stubCredStore{cred: "svc-cred"}
			routes := []domain.RouteEntry{{Prefix: toolName, BackendURI: "http://backend:8080"}}
			broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

			data := toolCallJSON("tools/call", toolName+"/action", id)
			resp := broker.Handle(context.Background(), data, "test")

			return bytes.Equal(resp, backendResp)
		},
		genSafeStr,
		gen.IntRange(1, 10000),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 9: Deny decisions always produce -32004 and no backend forwarding
//
// When the PolicyEngine denies a tool call, the Broker MUST return -32004
// and MUST NOT forward the request to any backend.
// Validates: Requirements 3.4, 4.4
// ---------------------------------------------------------------------------

func TestProperty9_DenyDecisionsProduceMinus32004(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("denied tool call produces -32004 and no backend forward", prop.ForAll(
		func(toolName, denialReason string) bool {
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "u1", Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{
				Permitted:    false,
				DenialReason: denialReason,
			}}
			transport := &recordingTransport{}
			minter := &stubMinter{token: "signed-jwt"}
			creds := &stubCredStore{cred: "svc-cred"}
			routes := []domain.RouteEntry{{Prefix: toolName, BackendURI: "http://backend:8080"}}
			broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

			data := toolCallJSON("tools/call", toolName+"/action", 1)
			resp := broker.Handle(context.Background(), data, "test")

			// Must return -32004.
			if errorCodeFromResponse(resp) != domain.CodePolicyDenied {
				return false
			}
			// Must NOT have forwarded to any backend.
			return len(transport.forwardedTo) == 0
		},
		genSafeStr,
		genSafeStr,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 13: Raw credential never forwarded to backends
//
// The caller's raw Bearer token MUST NOT appear in any value passed to
// BackendTransport.Forward (neither as identityToken nor as service credential).
// Validates: Requirements 4.5
// ---------------------------------------------------------------------------

func TestProperty13_RawCredentialNeverForwarded(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("raw Bearer token never appears in forwarded values", prop.ForAll(
		func(toolName, rawToken, assertionToken string) bool {
			if rawToken == assertionToken {
				return true // skip degenerate case
			}

			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "u1", Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
			transport := &recordingTransport{}
			minter := &stubMinter{token: assertionToken}
			creds := &stubCredStore{cred: "svc-cred-not-raw-token"}
			routes := []domain.RouteEntry{{Prefix: toolName, BackendURI: "http://backend:8080"}}
			broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

			// Inject the raw Bearer token into context (simulating SSE transport).
			ctx := injectBearerToken(context.Background(), rawToken)
			data := toolCallJSON("tools/call", toolName+"/action", 1)
			broker.Handle(ctx, data, "test")

			// The raw token must not appear in any forwarded identity token.
			for _, tok := range transport.capturedTokens {
				if tok == rawToken {
					return false
				}
			}
			// The raw token must not appear as a service credential.
			for _, cred := range transport.capturedCreds {
				if cred == rawToken {
					return false
				}
			}
			return true
		},
		genSafeStr,
		gen.RegexMatch(`[a-z0-9]{20,40}`), // raw token
		gen.RegexMatch(`[a-z0-9]{20,40}`), // assertion token (different)
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 16: Log entries for tool calls contain all required fields
//
// Every tool_call_received log entry MUST contain: request_id, caller_user_id,
// tool_name, transport_type, timestamp.
// Validates: Requirements 6.2
// ---------------------------------------------------------------------------

func TestProperty16_ToolCallLogContainsRequiredFields(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("tool_call_received log contains all required fields", prop.ForAll(
		func(toolName, userID, transportType string) bool {
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: userID, Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
			transport := &recordingTransport{}
			minter := &stubMinter{token: "signed-jwt"}
			creds := &stubCredStore{cred: "svc-cred"}
			routes := []domain.RouteEntry{{Prefix: toolName, BackendURI: "http://backend:8080"}}
			broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

			data := toolCallJSON("tools/call", toolName+"/action", 1)
			broker.Handle(context.Background(), data, transportType)

			// All required fields must be present in the log.
			return logger.hasFieldKey("request_id") &&
				logger.hasField("caller_user_id", userID) &&
				logger.hasFieldKey("tool_name") &&
				logger.hasField("transport_type", transportType) &&
				logger.hasFieldKey("timestamp")
		},
		genSafeStr,
		genSafeStr,
		gen.OneConstOf("sse", "stdio", "test"),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 17: Log entries for policy decisions contain all required fields
//
// Every policy_decision log entry MUST contain: request_id, caller_user_id,
// tool_name, decision_outcome, matched_rule_id.
// Validates: Requirements 6.3
// ---------------------------------------------------------------------------

func TestProperty17_PolicyDecisionLogContainsRequiredFields(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 17a: permit decision
	properties.Property("permit decision log contains all required fields", prop.ForAll(
		func(toolName, userID, ruleID string) bool {
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: userID, Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: ruleID}}
			transport := &recordingTransport{}
			minter := &stubMinter{token: "signed-jwt"}
			creds := &stubCredStore{cred: "svc-cred"}
			routes := []domain.RouteEntry{{Prefix: toolName, BackendURI: "http://backend:8080"}}
			broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

			data := toolCallJSON("tools/call", toolName+"/action", 1)
			broker.Handle(context.Background(), data, "test")

			return logger.hasFieldKey("request_id") &&
				logger.hasField("caller_user_id", userID) &&
				logger.hasFieldKey("tool_name") &&
				logger.hasField("decision_outcome", "permit") &&
				logger.hasField("matched_rule_id", ruleID)
		},
		genSafeStr, genSafeStr, genSafeStr,
	))

	// 17b: deny decision
	properties.Property("deny decision log contains all required fields", prop.ForAll(
		func(toolName, userID, ruleID string) bool {
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: userID, Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: false, MatchedRuleID: ruleID, DenialReason: "denied"}}
			transport := &recordingTransport{}
			minter := &stubMinter{token: "signed-jwt"}
			creds := &stubCredStore{cred: "svc-cred"}
			routes := []domain.RouteEntry{{Prefix: toolName, BackendURI: "http://backend:8080"}}
			broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

			data := toolCallJSON("tools/call", toolName+"/action", 1)
			broker.Handle(context.Background(), data, "test")

			return logger.hasFieldKey("request_id") &&
				logger.hasField("caller_user_id", userID) &&
				logger.hasFieldKey("tool_name") &&
				logger.hasField("decision_outcome", "deny") &&
				logger.hasField("matched_rule_id", ruleID)
		},
		genSafeStr, genSafeStr, genSafeStr,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 18: Sensitive values never appear in log output
//
// Raw Bearer tokens, SAML assertions, and service credentials MUST NOT appear
// in any log entry emitted by the Broker.
// Validates: Requirements 6.6
// ---------------------------------------------------------------------------

func TestProperty18_SensitiveValuesNeverInLogs(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	properties.Property("raw Bearer token never appears in log output", prop.ForAll(
		func(toolName, rawToken string) bool {
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "u1", Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
			transport := &recordingTransport{}
			minter := &stubMinter{token: "signed-jwt-not-raw"}
			creds := &stubCredStore{cred: "svc-cred-not-raw"}
			routes := []domain.RouteEntry{{Prefix: toolName, BackendURI: "http://backend:8080"}}
			broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

			ctx := injectBearerToken(context.Background(), rawToken)
			data := toolCallJSON("tools/call", toolName+"/action", 1)
			broker.Handle(ctx, data, "test")

			return !logger.containsSensitiveValue(rawToken)
		},
		genSafeStr,
		gen.RegexMatch(`[a-z0-9]{20,40}`),
	))

	properties.Property("service credential never appears in log output", prop.ForAll(
		func(toolName, svcCred string) bool {
			logger := &capturingLogger{}
			identity := &stubIdentityService{identity: domain.IdentityContext{UserID: "u1", Groups: []string{"dev"}}}
			policy := &stubPolicyEngine{decision: domain.PolicyDecision{Permitted: true, MatchedRuleID: "r1"}}
			transport := &recordingTransport{}
			minter := &stubMinter{token: "signed-jwt"}
			creds := &stubCredStore{cred: svcCred}
			routes := []domain.RouteEntry{{Prefix: toolName, BackendURI: "http://backend:8080"}}
			broker := defaultBroker(identity, policy, transport, minter, creds, logger, routes)

			data := toolCallJSON("tools/call", toolName+"/action", 1)
			broker.Handle(context.Background(), data, "test")

			return !logger.containsSensitiveValue(svcCred)
		},
		genSafeStr,
		gen.RegexMatch(`[a-z0-9]{20,40}`),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// errorCodeFromResponse extracts the JSON-RPC error code from a response.
// Returns 0 if the response has no error.
func errorCodeFromResponse(data []byte) int {
	var resp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil || resp.Error == nil {
		return 0
	}
	return resp.Error.Code
}

// injectBearerToken stores a Bearer token in the context using authctx,
// simulating what the SSE transport does when it receives an Authorization: Bearer header.
func injectBearerToken(ctx context.Context, token string) context.Context {
	return authctx.WithBearerToken(ctx, token)
}
