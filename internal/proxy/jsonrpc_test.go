// Package proxy_test contains unit tests for JSON-RPC 2.0 parsing and error
// response construction.
//
// These tests cover:
//   - ParseToolCall: valid requests parse correctly (Req 1.2)
//   - ParseToolCall: invalid JSON → ErrInvalidRequest / code -32600 (Req 1.5)
//   - ParseToolCall: missing jsonrpc field → ErrInvalidRequest (Req 1.5)
//   - ParseToolCall: wrong jsonrpc version → ErrInvalidRequest (Req 1.5)
//   - ParseToolCall: missing method field → ErrInvalidRequest (Req 1.5)
//   - ErrorResponse: correct JSON-RPC 2.0 error structure
//   - JSON-RPC error code constants match spec values
//
// Requirements: 1.2, 1.5
package proxy_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/proxy"
)

// ---------------------------------------------------------------------------
// ParseToolCall tests
// ---------------------------------------------------------------------------

// TestParseToolCall_ValidRequest verifies that a well-formed JSON-RPC 2.0
// request parses into a ToolCall with the correct fields (Req 1.2).
func TestParseToolCall_ValidRequest(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github/create-pr","arguments":{}}}`)
	call, err := proxy.ParseToolCall(raw)
	if err != nil {
		t.Fatalf("ParseToolCall: unexpected error: %v", err)
	}
	if call.JSONRPC != "2.0" {
		t.Errorf("JSONRPC: got %q, want 2.0", call.JSONRPC)
	}
	if call.Method != "tools/call" {
		t.Errorf("Method: got %q, want tools/call", call.Method)
	}
	if call.Params == nil {
		t.Error("Params: expected non-nil")
	}
}

// TestParseToolCall_ValidListTools verifies that a list_tools request parses correctly.
func TestParseToolCall_ValidListTools(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":"req-abc","method":"tools/list"}`)
	call, err := proxy.ParseToolCall(raw)
	if err != nil {
		t.Fatalf("ParseToolCall: unexpected error: %v", err)
	}
	if call.Method != "tools/list" {
		t.Errorf("Method: got %q, want tools/list", call.Method)
	}
}

// TestParseToolCall_NullID verifies that a request with a null id parses correctly.
func TestParseToolCall_NullID(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":null,"method":"tools/call"}`)
	_, err := proxy.ParseToolCall(raw)
	if err != nil {
		t.Fatalf("ParseToolCall: unexpected error for null id: %v", err)
	}
}

// TestParseToolCall_InvalidJSON verifies that non-JSON input returns
// ErrInvalidRequest (Req 1.5).
func TestParseToolCall_InvalidJSON(t *testing.T) {
	raw := []byte(`not json at all`)
	_, err := proxy.ParseToolCall(raw)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

// TestParseToolCall_EmptyInput verifies that empty input returns ErrInvalidRequest.
func TestParseToolCall_EmptyInput(t *testing.T) {
	_, err := proxy.ParseToolCall([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

// TestParseToolCall_WrongJSONRPCVersion verifies that a request with
// jsonrpc != "2.0" returns ErrInvalidRequest (Req 1.5).
func TestParseToolCall_WrongJSONRPCVersion(t *testing.T) {
	cases := []string{
		`{"jsonrpc":"1.0","id":1,"method":"tools/call"}`,
		`{"jsonrpc":"","id":1,"method":"tools/call"}`,
		`{"jsonrpc":"3.0","id":1,"method":"tools/call"}`,
	}
	for _, raw := range cases {
		_, err := proxy.ParseToolCall([]byte(raw))
		if err == nil {
			t.Errorf("expected error for jsonrpc=%q, got nil", raw)
			continue
		}
		if !errors.Is(err, domain.ErrInvalidRequest) {
			t.Errorf("expected ErrInvalidRequest for %q, got: %v", raw, err)
		}
	}
}

// TestParseToolCall_MissingMethod verifies that a request without a method
// field returns ErrInvalidRequest (Req 1.5).
func TestParseToolCall_MissingMethod(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1}`)
	_, err := proxy.ParseToolCall(raw)
	if err == nil {
		t.Fatal("expected error for missing method, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

// TestParseToolCall_EmptyMethod verifies that a request with an empty method
// string returns ErrInvalidRequest (Req 1.5).
func TestParseToolCall_EmptyMethod(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":""}`)
	_, err := proxy.ParseToolCall(raw)
	if err == nil {
		t.Fatal("expected error for empty method, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

// TestParseToolCall_MissingJSONRPCField verifies that a request without the
// jsonrpc field returns ErrInvalidRequest (Req 1.5).
func TestParseToolCall_MissingJSONRPCField(t *testing.T) {
	raw := []byte(`{"id":1,"method":"tools/call"}`)
	_, err := proxy.ParseToolCall(raw)
	if err == nil {
		t.Fatal("expected error for missing jsonrpc field, got nil")
	}
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ErrorResponse tests
// ---------------------------------------------------------------------------

// TestErrorResponse_Structure verifies that ErrorResponse produces a valid
// JSON-RPC 2.0 error response with the correct structure.
func TestErrorResponse_Structure(t *testing.T) {
	resp := proxy.ErrorResponse(1, domain.CodeInvalidRequest, "invalid request")

	var parsed struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Result any `json:"result"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("unmarshal ErrorResponse: %v", err)
	}
	if parsed.JSONRPC != "2.0" {
		t.Errorf("jsonrpc: got %q, want 2.0", parsed.JSONRPC)
	}
	if parsed.Error == nil {
		t.Fatal("error field is nil")
	}
	if parsed.Error.Code != domain.CodeInvalidRequest {
		t.Errorf("error.code: got %d, want %d", parsed.Error.Code, domain.CodeInvalidRequest)
	}
	if parsed.Error.Message != "invalid request" {
		t.Errorf("error.message: got %q, want %q", parsed.Error.Message, "invalid request")
	}
	if parsed.Result != nil {
		t.Errorf("result should be nil in error response, got: %v", parsed.Result)
	}
}

// TestErrorResponse_NullID verifies that ErrorResponse handles nil id correctly.
func TestErrorResponse_NullID(t *testing.T) {
	resp := proxy.ErrorResponse(nil, domain.CodeInvalidRequest, "parse error")
	var parsed map[string]any
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["id"] != nil {
		t.Errorf("id: expected null, got %v", parsed["id"])
	}
}

// TestErrorResponse_StringID verifies that ErrorResponse handles string ids.
func TestErrorResponse_StringID(t *testing.T) {
	resp := proxy.ErrorResponse("req-abc", domain.CodePolicyDenied, "unauthorized: insufficient entitlements")
	var parsed map[string]any
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["id"] != "req-abc" {
		t.Errorf("id: got %v, want req-abc", parsed["id"])
	}
}

// ---------------------------------------------------------------------------
// JSON-RPC error code constant tests
// ---------------------------------------------------------------------------

// TestErrorCodeConstants verifies that the domain error code constants match
// the JSON-RPC 2.0 specification values used by Proxy_Core (Req 1.5).
func TestErrorCodeConstants(t *testing.T) {
	cases := []struct {
		name     string
		got      int
		expected int
	}{
		{"CodeInvalidRequest", domain.CodeInvalidRequest, -32600},
		{"CodeUnauthenticated", domain.CodeUnauthenticated, -32001},
		{"CodeServiceUnavailable", domain.CodeServiceUnavailable, -32002},
		{"CodeUnauthorized", domain.CodeUnauthorized, -32003},
		{"CodePolicyDenied", domain.CodePolicyDenied, -32004},
		{"CodeInvalidParams", domain.CodeInvalidParams, -32602},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.expected {
				t.Errorf("%s: got %d, want %d", tc.name, tc.got, tc.expected)
			}
		})
	}
}

// TestErrorResponse_AllErrorCodes verifies that ErrorResponse produces valid
// JSON for each defined error code.
func TestErrorResponse_AllErrorCodes(t *testing.T) {
	codes := []struct {
		code    int
		message string
	}{
		{domain.CodeInvalidRequest, "invalid request"},
		{domain.CodeUnauthenticated, "unauthenticated: no identity credential present"},
		{domain.CodeServiceUnavailable, "service unavailable: upstream dependency unreachable"},
		{domain.CodeUnauthorized, "unauthorized: invalid credential"},
		{domain.CodePolicyDenied, "unauthorized: insufficient entitlements"},
		{domain.CodeInvalidParams, "invalid params: no route configured for tool prefix"},
	}
	for _, tc := range codes {
		resp := proxy.ErrorResponse(1, tc.code, tc.message)
		var parsed map[string]any
		if err := json.Unmarshal(resp, &parsed); err != nil {
			t.Errorf("code %d: unmarshal error: %v", tc.code, err)
			continue
		}
		errObj, ok := parsed["error"].(map[string]any)
		if !ok {
			t.Errorf("code %d: error field missing or wrong type", tc.code)
			continue
		}
		gotCode := int(errObj["code"].(float64))
		if gotCode != tc.code {
			t.Errorf("code %d: got %d in response", tc.code, gotCode)
		}
	}
}

// TestSuccessResponse_Structure verifies that SuccessResponse produces a valid
// JSON-RPC 2.0 success response.
func TestSuccessResponse_Structure(t *testing.T) {
	result := map[string]any{"tools": []string{"github/create-pr"}}
	resp := proxy.SuccessResponse(42, result)

	var parsed struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Result  any    `json:"result"`
		Error   any    `json:"error"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("unmarshal SuccessResponse: %v", err)
	}
	if parsed.JSONRPC != "2.0" {
		t.Errorf("jsonrpc: got %q, want 2.0", parsed.JSONRPC)
	}
	if parsed.Result == nil {
		t.Error("result should be non-nil in success response")
	}
	if parsed.Error != nil {
		t.Errorf("error should be nil in success response, got: %v", parsed.Error)
	}
}
