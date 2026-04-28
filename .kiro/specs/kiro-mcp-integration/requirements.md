# Requirements Document

## Introduction

This feature wires Abaris — the identity-aware MCP proxy/broker — into Kiro as a registered MCP server. Once connected, Kiro will discover and invoke tools through Abaris rather than directly against backend MCP servers. Because Abaris enforces OPA-based group policies, different Kiro users (or different Cognito identity groups) will see different tool lists and have different call permissions, demonstrating end-to-end identity-aware tool access control from within the IDE.

The integration has two distinct concerns:

1. **Connection** — configuring Kiro to speak to Abaris over a supported transport (SSE or Stdio) with a valid Cognito credential.
2. **Demonstration** — verifying that the `developers` group sees the full `github/*` + `internal/*` tool set while the `read-only` group sees only the read/list/search subset, with write/delete tools absent from the discovery response.

## Glossary

- **Abaris** — the identity-aware MCP proxy/broker written in Go; the system under integration.
- **Kiro** — the AI-assisted IDE acting as the MCP client in this integration.
- **MCP** — Model Context Protocol; the JSON-RPC 2.0 protocol used between Kiro and Abaris.
- **SSE_Transport** — the Server-Sent Events HTTP transport Abaris exposes for inbound MCP connections.
- **Stdio_Transport** — the standard-input/output transport Abaris exposes for inbound MCP connections.
- **Cognito_Token** — a short-lived OIDC Bearer token issued by AWS Cognito; the credential Kiro presents to Abaris.
- **Cognito_Refresh_Token** — a long-lived token used by Abaris to silently renew an expired Cognito_Token without user interaction.
- **Identity_Context** — Abaris's internal normalized representation of a caller's identity, including `UserID`, `Groups`, and `Entitlements`.
- **OPA** — Open Policy Agent; the policy engine Abaris uses to evaluate tool access.
- **Policy_Decision** — the allow/deny result produced by OPA for a given Identity_Context and tool call.
- **Developers_Group** — the Cognito group whose members are granted `github/*` and `internal/*` tool access.
- **Read_Only_Group** — the Cognito group whose members are granted only read/list/search tools and denied write/delete tools.
- **Discovery** — the MCP `list_tools` operation; returns the filtered tool list for the caller's identity.
- **Execution** — the MCP `call_tool` operation; invokes a single tool after policy evaluation.
- **X_Abaris_Identity** — the KMS-signed JWT Abaris mints and forwards to backend servers on standard routes.
- **DryRun** — Abaris's pure-function policy simulation used in CI to validate policy changes before deployment.
- **Config_Directory** — the `/config/` directory containing `identity.yaml`, `routing.yaml`, and `policies/*.yaml`.

---

## Requirements

### Requirement 1: Kiro Registers Abaris as an MCP Server

**User Story:** As a developer, I want to register Abaris as an MCP server in Kiro's configuration, so that Kiro can discover and invoke tools through Abaris.

#### Acceptance Criteria

1. THE Kiro_Configuration SHALL include an entry that identifies Abaris as an MCP server with a name, transport type, and connection endpoint.
2. WHEN Kiro starts or reloads its MCP server list, THE Kiro_Configuration SHALL load the Abaris entry without requiring a full IDE restart.
3. THE Kiro_Configuration SHALL support both SSE and Stdio transport types for the Abaris entry, selectable by the operator.
4. IF the Abaris endpoint is unreachable at connection time, THEN THE Kiro_Configuration SHALL surface a connection error to the user identifying Abaris by name.
5. THE Kiro_Configuration SHALL not embed plaintext Cognito credentials; credential values SHALL be referenced via environment variables or a secrets reference.

---

### Requirement 2: Kiro Authenticates to Abaris with a Cognito Token

**User Story:** As a developer, I want Kiro to present my Cognito identity when connecting to Abaris, so that Abaris can enforce group-based policies on my behalf.

#### Acceptance Criteria

1. WHEN Kiro initiates an MCP connection to Abaris over SSE, THE SSE_Transport SHALL receive an `Authorization: Bearer <Cognito_Token>` header on every request.
2. WHEN Kiro initiates an MCP connection to Abaris over Stdio, THE Stdio_Transport SHALL receive the Cognito_Token via a configured environment variable or startup argument passed to the Abaris process.
3. WHEN the Cognito_Token presented by Kiro is valid, THE Abaris SHALL resolve the caller's Identity_Context including `UserID` and `Groups` before processing any MCP request.
4. WHEN the Cognito_Token presented by Kiro has expired and a Cognito_Refresh_Token is available, THE Abaris SHALL silently refresh the token and continue processing without returning an error to Kiro.
5. IF the Cognito_Token is absent or invalid and no valid Cognito_Refresh_Token is available, THEN THE Abaris SHALL return JSON-RPC error code `-32001` to Kiro.
6. THE Abaris SHALL never forward the raw Cognito_Token to any backend MCP server.

---

### Requirement 3: Kiro Discovers a Policy-Filtered Tool List

**User Story:** As a developer, I want Kiro's tool panel to show only the tools my identity group is permitted to use, so that I am not presented with tools I cannot invoke.

#### Acceptance Criteria

1. WHEN Kiro sends a `list_tools` request to Abaris, THE Abaris SHALL aggregate tool lists from all configured backend MCP servers using service credentials.
2. WHEN Kiro sends a `list_tools` request and the caller belongs to the Developers_Group, THE Abaris SHALL return all tools matching `github/*` and `internal/*` patterns.
3. WHEN Kiro sends a `list_tools` request and the caller belongs to the Read_Only_Group, THE Abaris SHALL return only tools matching `github/get-*`, `github/list-*`, `github/search-*`, `internal/get-*`, `internal/list-*`, `internal/read-*`, and `internal/fetch-*` patterns.
4. THE Discovery response returned to Kiro SHALL contain no tools that the caller's Identity_Context is not permitted to invoke.
5. WHEN the caller belongs to both the Developers_Group and the Read_Only_Group, THE Abaris SHALL union the allowed_tools patterns from both groups' policy entries before filtering.
6. IF a backend MCP server is unreachable during Discovery, THEN THE Abaris SHALL return the filtered tool list from the remaining reachable backends and log a WARN identifying the unreachable backend.

---

### Requirement 4: Policy Enforcement on Tool Execution

**User Story:** As a platform engineer, I want Abaris to enforce group policies on every tool call Kiro makes, so that identity-based access control is applied at execution time, not just at discovery time.

#### Acceptance Criteria

1. WHEN Kiro sends a `call_tool` request, THE Abaris SHALL evaluate the tool call against OPA policies using the caller's Identity_Context before forwarding to any backend.
2. WHEN the Policy_Decision is `allow`, THE Abaris SHALL forward the tool call to the appropriate backend using service credentials and return the backend response to Kiro unmodified.
3. WHEN the Policy_Decision is `deny`, THE Abaris SHALL return JSON-RPC error code `-32004` to Kiro and SHALL NOT forward the request to any backend.
4. WHEN a caller in the Read_Only_Group attempts to invoke a write or delete tool (e.g. `github/create-pr`, `github/delete-branch`), THE Abaris SHALL deny the call and return `-32004`.
5. WHEN a caller in the Developers_Group invokes any tool matching `github/*` or `internal/*`, THE Abaris SHALL allow the call and forward it to the backend.
6. IF the tool name in the `call_tool` request does not match any route prefix in `config/routing.yaml`, THEN THE Abaris SHALL return JSON-RPC error code `-32602` to Kiro.
7. THE Abaris SHALL log every tool call with `request_id`, `caller_user_id`, `tool_name`, and `decision_outcome` fields.

---

### Requirement 5: Observable Policy Differentiation

**User Story:** As a developer, I want to be able to demonstrate that two different Cognito identities see different tool lists in Kiro, so that I can verify the end-to-end policy enforcement is working correctly.

#### Acceptance Criteria

1. WHEN a Kiro session is authenticated as a Developers_Group member and a `list_tools` request is issued, THE Abaris SHALL return a tool list that includes write tools such as `github/create-pr`.
2. WHEN a Kiro session is authenticated as a Read_Only_Group member and a `list_tools` request is issued, THE Abaris SHALL return a tool list that excludes `github/create-pr` and all other write/delete tools.
3. THE tool list returned to a Read_Only_Group member SHALL be a strict subset of the tool list returned to a Developers_Group member for the same set of backend tools.
4. WHEN the `config/policies/developers.yaml` or `config/policies/read-only.yaml` file is modified on disk, THE Abaris SHALL hot-reload the updated policies within 5 seconds and apply them to subsequent `list_tools` and `call_tool` requests without restarting.
5. WHEN a policy hot-reload results in a cross-file validation failure (e.g. a policy references an undefined route prefix), THE Abaris SHALL retain the previous policy set and log a WARN identifying the offending file, group name, and undefined prefix.

---

### Requirement 6: Local Development Configuration

**User Story:** As a developer, I want a documented, runnable local configuration for the Kiro–Abaris integration, so that I can reproduce the policy differentiation demo on my workstation without deploying to AWS.

#### Acceptance Criteria

1. THE integration SHALL provide a sample Kiro MCP server configuration entry (JSON or YAML) that connects to a locally running Abaris instance over Stdio or SSE.
2. THE integration SHALL provide instructions for obtaining a Cognito_Token for each test identity (Developers_Group member and Read_Only_Group member) using the AWS CLI or a helper script.
3. WHEN Abaris is run locally with `type: badger` token store and a LocalStack KMS endpoint, THE Abaris SHALL start successfully without requiring live AWS credentials for DynamoDB or production KMS.
4. THE integration documentation SHALL describe the exact sequence of steps to: start Abaris locally, register it in Kiro, authenticate as each test identity, and observe the differing tool lists.
5. IF the local Abaris process exits unexpectedly, THEN THE Kiro_Configuration SHALL surface a disconnection error to the user within 10 seconds.

---

### Requirement 7: Security Invariants Preserved During Integration

**User Story:** As a security engineer, I want the Kiro–Abaris integration to preserve all existing Abaris security invariants, so that connecting Kiro does not weaken the access control model.

#### Acceptance Criteria

1. THE Abaris SHALL never include the raw Cognito_Token in any log output, structured log field, or error message returned to Kiro.
2. THE Abaris SHALL never forward the raw Cognito_Token to any backend MCP server regardless of transport type.
3. WHEN Abaris forwards a tool call to a backend, THE backend request SHALL include the `X_Abaris_Identity` JWT header containing the normalized Identity_Context.
4. THE X_Abaris_Identity JWT SHALL be signed using `kms:Sign` with the configured asymmetric KMS key; the private key SHALL never be loaded into Abaris process memory.
5. WHEN Kiro connects over SSE, THE SSE_Transport SHALL accept connections only over HTTPS in production deployments.
6. THE Kiro_Configuration SHALL not store Cognito_Token values at rest; tokens SHALL be sourced from environment variables or a credential helper at connection time.
