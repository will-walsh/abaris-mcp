package domain

import "errors"

// Sentinel errors for the Abaris domain layer.
// Infrastructure adapters wrap these with fmt.Errorf("...: %w", ErrXxx)
// so callers can use errors.Is for type-safe error handling.
var (
	// ErrUnauthenticated is returned when no identity credential is present.
	// Maps to JSON-RPC error code -32001.
	ErrUnauthenticated = errors.New("unauthenticated: no identity credential present")

	// ErrUnauthorized is returned when the credential is present but invalid or
	// expired, or when the PolicyEngine denies the tool call.
	// Maps to JSON-RPC error code -32003 (identity) or -32004 (policy).
	ErrUnauthorized = errors.New("unauthorized: insufficient entitlements")

	// ErrServiceUnavailable is returned when an upstream dependency (Identity
	// Provider, OPA, KMS) is unreachable.
	// Maps to JSON-RPC error code -32002.
	ErrServiceUnavailable = errors.New("service unavailable: upstream dependency unreachable")

	// ErrInvalidRequest is returned when the inbound MCP request does not
	// conform to JSON-RPC 2.0.
	// Maps to JSON-RPC error code -32600.
	ErrInvalidRequest = errors.New("invalid request: does not conform to JSON-RPC 2.0")

	// ErrNoRoute is returned when no route prefix matches the requested tool name.
	// Maps to JSON-RPC error code -32602.
	ErrNoRoute = errors.New("invalid params: no route configured for tool prefix")
)

// JSON-RPC 2.0 error codes used by Proxy_Core when mapping domain errors to
// wire responses.
const (
	CodeInvalidRequest     = -32600
	CodeServiceUnavailable = -32002
	CodeUnauthenticated    = -32001
	CodeUnauthorized       = -32003 // invalid/expired credential
	CodePolicyDenied       = -32004 // insufficient entitlements
	CodeInvalidParams      = -32602 // no route for tool prefix
)
