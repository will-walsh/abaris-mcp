package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// StdioTransport accepts inbound MCP requests over Stdio (stdin/stdout).
// Each line on stdin is treated as a complete JSON-RPC 2.0 request.
// Responses are written as newline-delimited JSON to stdout.
//
// Credentials are passed via environment variables:
//   - ABARIS_BEARER_TOKEN — OIDC Bearer token
//   - ABARIS_SAML_ASSERTION — SAML assertion XML
//
// This matches the MCP Stdio transport convention where credentials are
// established out-of-band before the process starts.
type StdioTransport struct {
	broker *Broker
	logger domain.Logger
	in     io.Reader
	out    io.Writer
}

// NewStdioTransport constructs a StdioTransport using os.Stdin and os.Stdout.
func NewStdioTransport(broker *Broker, logger domain.Logger) *StdioTransport {
	return &StdioTransport{
		broker: broker,
		logger: logger,
		in:     os.Stdin,
		out:    os.Stdout,
	}
}

// NewStdioTransportWithIO constructs a StdioTransport with custom I/O.
// Used in tests.
func NewStdioTransportWithIO(broker *Broker, logger domain.Logger, in io.Reader, out io.Writer) *StdioTransport {
	return &StdioTransport{
		broker: broker,
		logger: logger,
		in:     in,
		out:    out,
	}
}

// Run reads newline-delimited JSON-RPC 2.0 requests from stdin, dispatches
// each to the Broker, and writes the response to stdout.
// Blocks until ctx is cancelled or stdin is closed (EOF).
func (t *StdioTransport) Run(ctx context.Context) error {
	baseCtx := injectCredentialsFromEnv(ctx)

	scanner := bufio.NewScanner(t.in)
	// Allow lines up to 10 MiB (large tool call params).
	scanner.Buffer(make([]byte, 64*1024), 10<<20)

	enc := json.NewEncoder(t.out)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return nil // EOF — clean shutdown
		}

		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		resp := t.broker.Handle(baseCtx, line, "stdio")

		// Write the response as a single JSON object followed by a newline.
		var raw json.RawMessage = resp
		if err := enc.Encode(raw); err != nil {
			t.logger.Error("stdio: write response failed", "error", err)
		}
	}
}

// injectCredentialsFromEnv reads OIDC/SAML credentials from environment
// variables and stores them in the context for the identity adapters.
func injectCredentialsFromEnv(ctx context.Context) context.Context {
	if token := os.Getenv("ABARIS_BEARER_TOKEN"); token != "" {
		ctx = authctx.WithBearerToken(ctx, token)
	}
	if assertion := os.Getenv("ABARIS_SAML_ASSERTION"); assertion != "" {
		ctx = authctx.WithSAMLAssertion(ctx, assertion)
	}
	return ctx
}
