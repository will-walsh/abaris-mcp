// Package proxy implements the MCP Broker core: JSON-RPC 2.0 parsing,
// the Broker struct, Discovery (list_tools) and Execution (call_tool) flows,
// and the SSE and Stdio transport adapters.
//
// The Broker depends only on domain interfaces — no infrastructure imports.
// All adapters are wired at the composition root (cmd/abaris/main.go).
package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// jsonRPCError is the wire representation of a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// jsonRPCResponse is the wire representation of a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

// ParseToolCall parses raw JSON-RPC 2.0 bytes into a domain.ToolCall.
// Returns domain.ErrInvalidRequest if the bytes are not valid JSON-RPC 2.0:
//   - not valid JSON
//   - jsonrpc field is not "2.0"
//   - method field is empty
func ParseToolCall(data []byte) (domain.ToolCall, error) {
	var call domain.ToolCall
	if err := json.Unmarshal(data, &call); err != nil {
		return domain.ToolCall{}, fmt.Errorf("%w: %s", domain.ErrInvalidRequest, err)
	}
	if call.JSONRPC != "2.0" {
		return domain.ToolCall{}, fmt.Errorf("%w: jsonrpc field must be \"2.0\", got %q", domain.ErrInvalidRequest, call.JSONRPC)
	}
	if call.Method == "" {
		return domain.ToolCall{}, fmt.Errorf("%w: method field is required", domain.ErrInvalidRequest)
	}
	return call, nil
}

// ErrorResponse constructs a JSON-RPC 2.0 error response for the given id,
// code, and message. id may be nil for parse errors where the request ID
// could not be determined.
func ErrorResponse(id any, code int, message string) []byte {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: message},
	}
	b, _ := json.Marshal(resp)
	return b
}

// SuccessResponse constructs a JSON-RPC 2.0 success response.
func SuccessResponse(id any, result any) []byte {
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	b, _ := json.Marshal(resp)
	return b
}

// toolNameFromCall extracts the tool name from a ToolCall's Params JSON.
// Returns "" if Params is nil or does not contain a "name" field.
func toolNameFromCall(call domain.ToolCall) string {
	if call.Params == nil {
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
// For single-segment names (no "/"), the full name is returned.
func toolPrefix(toolName string) string {
	if i := strings.Index(toolName, "/"); i >= 0 {
		return toolName[:i]
	}
	return toolName
}

// originJTIFromToken extracts the "jti" claim from a compact JWT without
// verifying the signature. Returns "" if the token is not a valid JWT or
// has no "jti" claim. Used to populate ext_identity.origin_jti.
func originJTIFromToken(token string) string {
	if token == "" {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.JTI
}
