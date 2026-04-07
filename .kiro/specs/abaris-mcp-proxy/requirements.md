# Requirements Document

## Introduction

Abaris is a high-performance, identity-aware MCP (Model Context Protocol) Broker written in Go. It acts as the primary endpoint for AI/LLM clients and sits between those clients and internal enterprise backend MCP tool servers. Abaris intercepts all MCP requests, validates the caller's identity via federated identity protocols (OIDC or SAML 2.0), normalizes the resolved claims into an internal IdentityContext, and enforces a Policy_Engine backed by OPA (Open Policy Agent) that performs Scope Reduction — filtering the visible tool list and blocking tool calls that exceed the caller's entitlements before any request reaches a backend.

Abaris operates as a Broker, not a transparent proxy: it is the explicit, named endpoint that AI clients connect to. It handles MCP Discovery (returning a filtered `list_tools` response based on identity) and MCP Execution (routing `call_tool` to the correct backend using its own service credentials). The caller's raw token or assertion is never forwarded to backend servers.

All routing and policy configuration is expressed in a version-controlled Config_Directory (Config-as-Code). There is no management UI.

## Glossary

- **Abaris**: The MCP Broker system described in this document.
- **MCP**: Model Context Protocol — a JSON-RPC 2.0 based protocol for communication between LLM agents and tool servers, transported over Stdio or SSE.
- **Tool_Call**: An MCP JSON-RPC 2.0 request from a client that invokes a named backend tool with a set of parameters.
- **Broker**: The architectural role Abaris plays — it is the explicit, named endpoint for AI clients. It handles Discovery and Execution on behalf of clients, using its own service credentials for backend calls.
- **Discovery**: The MCP `list_tools` operation. Abaris filters the aggregated tool list from all backends to return only the tools the caller is permitted to invoke, based on their IdentityContext.
- **Execution**: The MCP `call_tool` operation. Abaris routes the request to the correct backend MCP server and returns the response to the client.
- **Federation**: The use of standard identity protocols (OIDC, SAML 2.0) to accept identity assertions from external Identity Providers without coupling to any vendor-specific SDK.
- **Identity_Provider**: An external identity system (e.g., Ping Identity, Okta, Azure AD) that issues OIDC tokens or SAML assertions for authenticated users.
- **OIDC**: OpenID Connect — an identity layer on top of OAuth 2.0. Abaris acts as a Relying Party, validating ID tokens using the provider's JWKS endpoint.
- **SAML**: Security Assertion Markup Language 2.0 — a federated identity protocol. Abaris acts as a Service Provider, validating assertions from an Identity Provider using the provider's metadata.
- **Relying_Party**: The OIDC role Abaris plays when validating OIDC ID tokens issued by an Identity_Provider.
- **Service_Provider**: The SAML 2.0 role Abaris plays when validating SAML assertions issued by an Identity_Provider.
- **IdentityContext**: The normalized internal representation of a resolved caller identity, containing UserID, Email, Groups, and Entitlements. Produced by the Identity_Service after validating an inbound token or assertion. Replaces any provider-specific claim format.
- **Identity_Service**: The Abaris component responsible for validating inbound tokens or assertions and normalizing them into an IdentityContext.
- **Proxy_Core**: The central Abaris component that receives MCP requests, orchestrates identity resolution, policy evaluation, Discovery filtering, and Execution routing.
- **Policy_Engine**: The Abaris component that evaluates whether a given Tool_Call is permitted for a given IdentityContext. Backed by an OPA evaluator using Rego policies.
- **OPA**: Open Policy Agent — a general-purpose, open-source policy engine that evaluates Rego policies to produce permit/deny decisions.
- **Rego**: The policy language used by OPA. Rego policies in Abaris define which Tool_Calls are permitted for each Group or Entitlement.
- **OPA_Bundle**: A versioned, distributable archive of Rego policy files and data that the Policy_Engine loads and evaluates.
- **OPA_Bundle_Server**: A remote HTTP server that serves OPA_Bundles. The Policy_Engine polls the OPA_Bundle_Server to receive updated policies without restarting Abaris.
- **Scope_Reduction**: The process of filtering the tool list (Discovery) or blocking a Tool_Call (Execution) when the caller's IdentityContext does not satisfy the active Rego policy.
- **Reduced_Scope**: The set of tools a caller is permitted to see and invoke, as determined by matching their IdentityContext Groups against policy entries in `abaris.yaml`.
- **Backend**: A downstream MCP tool server that Abaris routes requests to on behalf of permitted callers.
- **Service_Credentials**: The credentials Abaris uses to authenticate its own calls to Backend servers, retrieved from AWS Secrets Manager. The caller's token is never forwarded.
- **Identity_Assertion_Token**: A short-lived JWT minted and signed by Abaris using AWS KMS asymmetric signing (RS256), containing the normalized IdentityContext of the authenticated caller. Attached to backend requests in the `X-Abaris-Identity` header to provide full user attribution without exposing the caller's raw credential. The private key used for signing never leaves KMS.
- **KMS_Signing_Key**: An AWS KMS asymmetric key (RSA_2048 or RSA_4096, SIGN_VERIFY usage) used by Abaris to sign Identity_Assertion_Tokens. The private key never leaves KMS; Abaris calls the KMS Sign API for each token mint operation.
- **Structured_Logger**: The Abaris logging component using Go's `slog` package for structured, leveled log output.
- **Secrets_Manager**: AWS Secrets Manager, used to store and retrieve sensitive configuration such as Service_Credentials and Identity_Provider client secrets.
- **App_Runner**: AWS App Runner, the target deployment environment for Abaris.
- **Config_Directory**: The `/config/` directory containing `identity.yaml`, `routing.yaml`, and the `policies/` subdirectory. It is the on-disk representation of all Abaris configuration and is the single source of truth for routing, identity provider configuration, and policy definitions.
- **Policy_File**: A single YAML file in `config/policies/` contributing one or more `PolicyEntry` items. Multiple Policy_Files are deep-merged at load time and on hot reload.
- **Deep_Merge**: The process of combining `PolicyEntry` items from multiple Policy_Files. When two files define a `PolicyEntry` for the same group name, their `allowed_tools` and `denied_tools` lists are unioned (deduplicated), not replaced.
- **Hot_Reload**: The process of re-reading and re-merging all Policy_Files when a change is detected in `config/policies/`, without restarting Abaris. Hot_Reload does not apply to `identity.yaml` or `routing.yaml`.
- **abaris.yaml**: _(Deprecated — replaced by Config_Directory.)_ Previously the single Config-as-Code file. The equivalent configuration is now split across `config/identity.yaml`, `config/routing.yaml`, and `config/policies/*.yaml`.

---

## Requirements

### Requirement 1: MCP Protocol Compliance

**User Story:** As an LLM agent, I want to communicate with Abaris using the standard MCP protocol, so that I can discover and invoke backend tools without needing to know about the broker layer.

#### Acceptance Criteria

1. THE Proxy_Core SHALL accept inbound MCP JSON-RPC 2.0 requests over both Stdio and SSE transports.
2. WHEN a valid MCP Tool_Call request is received, THE Proxy_Core SHALL parse the request into a structured internal representation before processing.
3. WHEN Abaris forwards a permitted Tool_Call to the Backend, THE Proxy_Core SHALL preserve the original JSON-RPC 2.0 request structure, including method name, parameters, and request ID.
4. WHEN the Backend returns a response, THE Proxy_Core SHALL forward the response to the originating client without modification.
5. IF a received request does not conform to the MCP JSON-RPC 2.0 schema, THEN THE Proxy_Core SHALL return a JSON-RPC 2.0 error response with code `-32600` (Invalid Request) to the client.

---

### Requirement 2: Federated Identity Resolution

**User Story:** As a security architect, I want every inbound request to be associated with a verified, normalized identity, so that policy decisions are always grounded in authenticated claims regardless of which Identity Provider issued the token or assertion.

#### Acceptance Criteria

1. WHEN a Tool_Call is received, THE Identity_Service SHALL extract the caller's credential from the request context — a Bearer token for OIDC or a SAML assertion for SAML 2.0 transport.
2. WHEN an OIDC Bearer token is extracted, THE Identity_Service SHALL validate the token's signature, expiry, issuer, and audience using the configured JWKS endpoint and Discovery URL via the `zitadel/oidc` library.
3. WHEN a SAML assertion is extracted, THE Identity_Service SHALL validate the assertion's signature and conditions using the configured Identity_Provider metadata URL via the `crewjam/saml` library.
4. WHEN a token or assertion is successfully validated, THE Identity_Service SHALL normalize the provider-specific claims into an IdentityContext containing: UserID, Email, Groups, and Entitlements.
5. THE Identity_Service SHALL support multiple Identity_Provider configurations simultaneously, selecting the correct provider based on the token issuer or assertion issuer present in the inbound credential.
6. IF the credential is absent from the request, THEN THE Identity_Service SHALL return an unauthenticated error, and THE Proxy_Core SHALL return a JSON-RPC 2.0 error response with code `-32001` to the client.
7. IF the Identity_Provider is unreachable during validation, THEN THE Identity_Service SHALL return a service-unavailable error, and THE Proxy_Core SHALL return a JSON-RPC 2.0 error response with code `-32002` to the client.
8. IF the credential is present but invalid, expired, or fails signature validation, THEN THE Identity_Service SHALL return an unauthorized error, and THE Proxy_Core SHALL return a JSON-RPC 2.0 error response with code `-32003` to the client.
9. THE Identity_Service SHALL cache resolved IdentityContext values for a configurable TTL to reduce latency on repeated calls from the same identity.
10. THE Identity_Service SHALL use only the `zitadel/oidc` library for OIDC validation and only the `crewjam/saml` library for SAML validation; no vendor-specific identity SDK SHALL be used.

---

### Requirement 3: Policy Enforcement and Scope Reduction

**User Story:** As an enterprise security officer, I want Abaris to enforce group-based access control on every tool discovery and tool call using OPA Rego policies, so that users can only see and invoke tools that match the permissions defined for their normalized identity Groups.

#### Acceptance Criteria

1. WHEN an IdentityContext has been resolved for a caller, THE Policy_Engine SHALL evaluate whether the requested Tool_Call is permitted by submitting the caller's Groups, Entitlements, and the Tool_Call details as input to the OPA evaluator.
2. THE Policy_Engine SHALL load and evaluate Rego policies from an OPA_Bundle, where each policy defines the set of permitted Tool_Calls for one or more Groups or Entitlements.
3. WHEN a caller's Groups and Entitlements include only `read-only`, THE Policy_Engine SHALL deny any Tool_Call whose name or declared operation type is classified as a WRITE or DELETE operation, as defined in the active Rego policy.
4. WHEN THE Policy_Engine denies a Tool_Call, THE Proxy_Core SHALL return a JSON-RPC 2.0 error response with code `-32004` and a message of `"unauthorized: insufficient entitlements"` to the client, without forwarding the request to the Backend.
5. WHEN THE Policy_Engine permits a Tool_Call, THE Proxy_Core SHALL forward the request to the Backend within 50ms of the policy decision (excluding network latency to the Backend).
6. WHEN the OPA_Bundle is updated on the OPA_Bundle_Server or local filesystem, THE Policy_Engine SHALL reload the updated Rego policies without requiring a restart of Abaris.
7. IF a Tool_Call's operation type cannot be determined from the request, THEN THE Policy_Engine SHALL apply a deny-by-default decision and THE Proxy_Core SHALL return a `-32004` error to the client.
8. THE Policy_Engine SHALL record the identifier of the matched Rego policy rule in the permit or deny decision result, so that the Structured_Logger can include it in audit log entries.

---

### Requirement 4: MCP Broker — Discovery and Execution

**User Story:** As an LLM agent, I want Abaris to act as a Broker so that I receive only the tools I am permitted to use during discovery, and so that my tool calls are routed to the correct backend without me needing to know backend addresses or credentials.

#### Acceptance Criteria

1. WHEN a `list_tools` (Discovery) request is received, THE Proxy_Core SHALL aggregate the tool lists from all configured Backend servers and return only the subset of tools that the caller's IdentityContext is permitted to invoke, as determined by the Policy_Engine.
2. WHEN a `call_tool` (Execution) request is received for a permitted tool, THE Proxy_Core SHALL route the request to the Backend whose route prefix matches the tool name, as configured in `routing.yaml`.
3. WHEN THE Proxy_Core calls a Backend server, THE Proxy_Core SHALL authenticate to Backend servers using Service_Credentials retrieved from Secrets_Manager.
4. WHEN THE Proxy_Core calls a Backend server, THE Proxy_Core SHALL mint a short-lived, signed Identity_Assertion_Token (a JWT) containing the caller's normalized IdentityContext (UserID, Email, Groups, Entitlements, Provider) and attach it to every backend request in the `X-Abaris-Identity` header. Abaris SHALL mint the Identity_Assertion_Token by calling the AWS KMS Sign API using a configured asymmetric KMS_Signing_Key; the private key SHALL never be loaded into process memory.
5. The caller's raw inbound Bearer token or SAML assertion SHALL NOT be forwarded to any Backend.
6. THE Identity_Assertion_Token SHALL have a configurable TTL (default: 60 seconds) and SHALL include the following claims: standard OIDC top-level claims `iss` (Abaris's configured issuer), `sub` (IdentityContext.UserID), `aud` (configured audience from `routing.yaml`), `iat`, and `exp`; plus a nested `ext_identity` object containing `origin_jti` (the `jti` of the inbound Cognito token), `groups`, `entitlements`, and `provider` from the IdentityContext. This structure ensures any standard OIDC library at the destination can parse and validate the token without custom code.
7. Abaris SHALL expose a `GET /.well-known/jwks.json` endpoint that returns the public key corresponding to the KMS_Signing_Key, so that Backend servers MAY validate Identity_Assertion_Tokens independently.
8. IF a `call_tool` request is received for a tool that does not appear in the caller's Reduced_Scope, THEN THE Proxy_Core SHALL return a JSON-RPC 2.0 error response with code `-32004` without contacting any Backend.
9. IF no route is configured in `routing.yaml` for the tool name prefix of a permitted Tool_Call, THEN THE Proxy_Core SHALL return a JSON-RPC 2.0 error response with code `-32602` (Invalid Params) to the client.
10. THE Proxy_Core SHALL resolve the Backend URL for a Tool_Call by matching the tool name's leading segment (the prefix before the first `/`) against the `routes` entries in `routing.yaml`.

---

### Requirement 5: Config-as-Code (Config_Directory)

**User Story:** As a platform engineer, I want all Abaris routing, identity provider, and policy configuration to be expressed in a version-controlled directory structure, so that the system's behavior is fully auditable, reproducible, and supports per-team policy ownership via GitOps workflows without a management UI.

#### Acceptance Criteria

1. THE Proxy_Core SHALL load all routing, identity provider, and policy configuration exclusively from the Config_Directory at startup; no management UI or runtime configuration API SHALL exist. The Config_Directory SHALL contain:
   - `identity.yaml` — the `identity_providers` section
   - `routing.yaml` — the `routes` and `assertion` sections
   - `policies/` — a subdirectory containing one or more Policy_Files (`*.yaml`), each contributing one or more `PolicyEntry` items
2. THE `identity.yaml` file SHALL contain an `identity_providers` section with one or more provider entries, each specifying: provider type (`oidc` or `saml`), and type-specific fields as follows:
   - For OIDC: `discovery_url`, `jwks_endpoint`, `client_id`, and `audience`.
   - For SAML: `metadata_url`, `sp_entity_id`, `acs_url`, and paths to the SP certificate and private key (`cert_path`, `key_path`).
3. THE `routing.yaml` file SHALL contain a `routes` section with one or more entries, each specifying a `prefix` (the leading tool name segment) and a `backend_uri` (the internal HTTP(S) URL of the Backend MCP server for that prefix), and an `assertion` section with Identity Assertion Token minting configuration.
4. EACH Policy_File in `config/policies/` SHALL contain a `policies` section with one or more entries, each specifying a `group` (a normalized IdentityContext Group name) and a `reduced_scope` object with `allowed_tools` and optionally `denied_tools` lists of tool name glob patterns. THE `config.Loader` SHALL perform a Deep_Merge of all Policy_Files: for duplicate group names across files, `allowed_tools` and `denied_tools` lists SHALL be unioned (deduplicated), not replaced.
5. IF the Config_Directory or any required file (`identity.yaml`, `routing.yaml`) is absent at startup, THEN THE Proxy_Core SHALL log a fatal error and terminate with a non-zero exit code.
6. IF any config file contains a schema validation error (missing required field, invalid URL, unrecognised provider type), THEN THE Proxy_Core SHALL log a fatal error identifying the invalid field and terminate with a non-zero exit code.
7. AT startup, after loading and merging all configuration, THE `config.Loader` SHALL validate that every route prefix referenced in any policy's `allowed_tools` or `denied_tools` pattern exists as a `prefix` in `routing.yaml`. IF a policy references an undefined route prefix, THEN THE Proxy_Core SHALL log a fatal error identifying the Policy_File, group name, and undefined prefix, and terminate with a non-zero exit code.
8. THE `config.Loader` SHALL watch the `policies/` subdirectory using `github.com/fsnotify/fsnotify`. WHEN any `*.yaml` file in `policies/` is created, modified, or deleted, THE `config.Loader` SHALL re-read and re-merge all Policy_Files and atomically swap the active `PolicyEntry` slice in the running Broker. Hot_Reload SHALL NOT apply to `identity.yaml` or `routing.yaml`; changes to those files require a process restart.
9. IF a Hot_Reload cycle produces a cross-file validation error (a policy references an undefined route prefix), THE `config.Loader` SHALL reject the reload, log a warning identifying the offending Policy_File, group name, and undefined prefix, and retain the previously active policies unchanged.
10. THE Proxy_Core SHALL treat `identity.yaml` and `routing.yaml` as immutable at runtime; changes to those files require a process restart.
11. FOR ALL valid Config_Directory contents, loading the directory into a `domain.Config` struct and re-serializing each file SHALL produce documents that parse to an equivalent `domain.Config` struct (round-trip property).

---

### Requirement 6: Structured Logging and Observability

**User Story:** As a platform engineer, I want every broker decision to be recorded in structured logs, so that I can audit access patterns and diagnose issues in production.

#### Acceptance Criteria

1. THE Structured_Logger SHALL emit log entries in JSON format using Go's `slog` package.
2. WHEN a Tool_Call is received, THE Structured_Logger SHALL emit a log entry containing: request ID, caller UserID, tool name, transport type, and timestamp.
3. WHEN THE Policy_Engine makes a permit or deny decision, THE Structured_Logger SHALL emit a log entry containing: request ID, caller UserID, tool name, decision outcome, and the matched policy rule identifier.
4. WHEN an error occurs during identity resolution or policy evaluation, THE Structured_Logger SHALL emit a log entry at ERROR level containing: request ID, error type, and a non-sensitive description of the failure.
5. THE Structured_Logger SHALL support configurable log levels (DEBUG, INFO, WARN, ERROR) set via an environment variable.
6. THE Structured_Logger SHALL never include raw identity tokens, SAML assertions, passwords, or secret values in any log entry.

---

### Requirement 7: Secrets and Configuration Management

**User Story:** As a DevOps engineer, I want Abaris to retrieve sensitive credentials from AWS Secrets Manager at startup, so that no credentials are stored in environment variables or configuration files.

#### Acceptance Criteria

1. WHEN Abaris starts, THE Proxy_Core SHALL retrieve Service_Credentials and Identity_Provider client secrets from Secrets_Manager using the AWS SDK.
2. WHEN Abaris starts, THE Proxy_Core SHALL retrieve the public key for the configured KMS_Signing_Key via the KMS `GetPublicKey` API and cache it in memory for use by the JWKS endpoint.
3. IF Secrets_Manager is unreachable at startup, THEN THE Proxy_Core SHALL log a fatal error via the Structured_Logger and terminate with a non-zero exit code.
4. IF a required secret is missing from Secrets_Manager, THEN THE Proxy_Core SHALL log a fatal error identifying the missing secret key and terminate with a non-zero exit code.
5. THE Proxy_Core SHALL accept the AWS region and Secrets_Manager secret ARNs as environment variables, with no default values, so that misconfigured deployments fail explicitly.
6. WHERE the deployment environment supports IAM role-based access, THE Proxy_Core SHALL use the ambient IAM role credentials rather than static AWS access keys.
7. IF the KMS_Signing_Key is unreachable or the IAM role lacks `kms:Sign` permission at startup, THE Proxy_Core SHALL log a fatal error and terminate with a non-zero exit code.

---

### Requirement 8: Hexagonal Architecture and Testability

**User Story:** As a senior Go engineer, I want the codebase to follow Hexagonal Architecture, so that core domain logic is decoupled from infrastructure and can be tested in isolation.

#### Acceptance Criteria

1. THE Proxy_Core SHALL depend only on Go interfaces for the Identity_Service, Policy_Engine, Backend transport, and Structured_Logger — not on concrete implementations.
2. THE Identity_Service interface SHALL expose a method that accepts a request context and returns an IdentityContext (containing UserID, Email, Groups, and Entitlements) or a typed error; the interface SHALL not expose any OIDC or SAML library types in its signature.
3. THE Identity_Service interface SHALL be implementable by both an OIDC adapter (using `zitadel/oidc`) and a SAML adapter (using `crewjam/saml`), with the composition root selecting and wiring the correct adapter(s) based on `abaris.yaml` configuration.
4. THE Policy_Engine interface SHALL expose a method that accepts an IdentityContext and a Tool_Call and returns a typed permit/deny decision with a matched Rego rule identifier.
5. THE Policy_Engine interface SHALL be backed in production by an OPA evaluator that loads Rego policies from an OPA_Bundle; the interface SHALL remain independent of the OPA SDK so that alternative evaluators can be substituted.
6. WHEN unit tests are executed, THE Identity_Service and Policy_Engine implementations SHALL be replaceable with in-memory test doubles without modifying Proxy_Core logic.
7. THE Proxy_Core SHALL be deployable as a standalone binary with all infrastructure adapters (SSE, Stdio, AWS SDK, OIDC adapter, SAML adapter, OPA evaluator) wired at the composition root.

---

### Requirement 9: AWS App Runner Deployment

**User Story:** As a DevOps engineer, I want Abaris to be deployable on AWS App Runner, so that it scales automatically and requires minimal infrastructure management.

#### Acceptance Criteria

1. THE Proxy_Core SHALL expose an HTTP health check endpoint at `GET /health` that returns HTTP 200 when the service is ready to accept requests.
2. WHEN the health check endpoint is called and a required dependency (Identity_Provider or Backend) is unavailable, THE Proxy_Core SHALL return HTTP 503 with a JSON body indicating which dependency is degraded.
3. THE Proxy_Core SHALL emit all log output to stdout so that App_Runner can forward logs to CloudWatch without additional configuration.
4. THE Proxy_Core SHALL handle OS signals `SIGTERM` and `SIGINT` by completing in-flight requests and shutting down gracefully within a configurable drain timeout.
5. WHERE the App_Runner environment provides a `PORT` environment variable, THE Proxy_Core SHALL bind the SSE transport listener to that port.
6. THE IAM role assigned to the Abaris App_Runner service SHALL have the following minimum KMS permissions on the KMS_Signing_Key: `kms:Sign`, `kms:GetPublicKey`, and `kms:DescribeKey`.

---

## OBO Proxy Extension

> The following requirements extend Abaris into a **Stateful OBO (On-Behalf-Of) Proxy**. Instead of using Abaris's own service credentials for all backend calls, Abaris acquires and manages per-user downstream tokens (User Access Tokens) so that backend systems receive requests attributed to the actual end-user, not to the Abaris service account.

### Glossary Additions

- **OBO_Proxy**: The Abaris subsystem that manages per-user downstream tokens and injects them into outbound backend requests on behalf of the authenticated caller.
- **Secondary_Provider**: An OAuth2 authorization server (e.g. GitHub OAuth App) that issues User Access Tokens for downstream backend systems. Distinct from the Primary_Provider (Cognito) that authenticates the inbound caller.
- **Primary_Provider**: The Cognito OIDC provider that authenticates inbound callers. Abaris manages the Cognito session refresh silently; clients send a token once and Abaris refreshes it as needed.
- **UAT**: User Access Token — a short-lived OAuth2 access token issued by a Secondary_Provider, scoped to a specific user's downstream identity (e.g. a GitHub personal access token issued via OAuth App flow).
- **Token_Pair**: A pair of `(access_token, refresh_token)` for a given user and provider, stored encrypted in the Token_Store.
- **Token_Store**: The Abaris component that persists encrypted Token_Pairs per user per provider. Backed by DynamoDB in production or BadgerDB in development, selected via config.
- **Token_Registry**: The `internal/auth/registry.go` module that implements the `TokenStore` interface and its two concrete backends.
- **Refresh_Transport**: The `internal/proxy/refresh_transport.go` module that wraps the outbound HTTP transport with retry-on-401 logic, transparently refreshing the downstream UAT when the backend rejects it.
- **Connect_Flow**: The OAuth2 authorization code flow initiated by the `/connect/{provider}` endpoint. Used to onboard a user to a Secondary_Provider for the first time, or to re-authorize after a refresh token has been revoked.
- **OBO_Pipeline**: The per-request processing pipeline for OBO-enabled tool calls: (A) Cognito authn + silent refresh → (B) OPA authz → (C) UAT retrieval → (D) downstream refresh on 401 → forward with user UAT + X-Abaris-Assertion.
- **X-Abaris-Assertion**: The outbound header carrying the KMS-signed Identity Assertion JWT. Replaces and supersedes the `X-Abaris-Identity` header for OBO-enabled backends. Both header names are supported during migration.
- **KMS_Encryption_Key**: The AWS KMS symmetric key (AES-256-GCM via `kms:Encrypt` / `kms:Decrypt`) used to encrypt Token_Pairs at rest in the Token_Store. For the initial implementation this is the same KMS key as the KMS_Signing_Key, but the interface must support separate keys in future.
- **Cognito_Refresh_Token**: The OAuth2 refresh token issued by AWS Cognito alongside the inbound access token. Stored in the Token_Store under provider name `"cognito"` and used by Abaris to silently refresh the Cognito session when the access token expires.
- **Provider_Config**: A new section in `config/identity.yaml` that describes a Secondary_Provider: its OAuth2 authorization endpoint, token endpoint, client ID, client secret (from Secrets Manager), and requested scopes.

---

### Requirement 10: Multi-IdP Configuration

**User Story:** As a platform engineer, I want Abaris to support a configurable secondary OAuth2 provider alongside the primary Cognito OIDC provider, so that I can onboard users to downstream systems (e.g. GitHub) without hardcoding any provider-specific logic.

#### Acceptance Criteria

1. THE `config.Loader` SHALL support one or more `secondary_providers` entries in `config/identity.yaml`, each specifying: `name` (unique string), `type` (`oauth2`), `auth_url`, `token_url`, `client_id`, `client_secret_arn` (AWS Secrets Manager ARN), and `scopes` (list of strings).
2. WHEN Abaris starts, THE `config.Loader` SHALL retrieve the `client_secret` for each Secondary_Provider from Secrets_Manager using the configured `client_secret_arn`, and make it available to the Connect_Flow and Refresh_Transport components.
3. THE `config.Loader` SHALL validate that each Secondary_Provider entry has a unique `name`, a valid `auth_url`, a valid `token_url`, a non-empty `client_id`, a non-empty `client_secret_arn`, and at least one scope. IF any validation fails, THEN THE Proxy_Core SHALL log a fatal error and terminate with a non-zero exit code.
4. THE Secondary_Provider configuration SHALL be treated as immutable at runtime; changes require a process restart. Hot_Reload SHALL NOT apply to `secondary_providers` entries.
5. THE OBO_Proxy SHALL be provider-agnostic: no Secondary_Provider-specific logic SHALL appear outside of the `Provider_Config` struct and the Connect_Flow handler. GitHub is a valid example provider but SHALL NOT be hardcoded anywhere in the implementation.

---

### Requirement 11: Encrypted Token Registry

**User Story:** As a security architect, I want all per-user downstream tokens to be stored encrypted at rest, so that a compromise of the storage backend does not expose user credentials.

#### Acceptance Criteria

1. THE Token_Registry SHALL expose a `TokenStore` interface with three methods: `Get(ctx, userID, provider) (TokenPair, error)`, `Save(ctx, userID, provider, pair TokenPair) error`, and `Delete(ctx, userID, provider) error`. The primary key SHALL be the Cognito `sub` claim (IdentityContext.UserID).
2. THE Token_Registry SHALL support two backend implementations selected via `token_store.type` in `config/identity.yaml`: `dynamodb` (production) and `badger` (development/local). IF `token_store.type` is absent or invalid, THEN THE Proxy_Core SHALL log a fatal error and terminate.
3. WHEN `Save` is called, THE Token_Registry SHALL encrypt the Token_Pair using `kms:Encrypt` with the configured KMS_Encryption_Key before writing to the storage backend. WHEN `Get` is called, THE Token_Registry SHALL decrypt the stored ciphertext using `kms:Decrypt` before returning the Token_Pair.
4. THE `TokenStore` interface SHALL accept a `kmsKeyARN` parameter at construction time for the encryption key. For the initial implementation the same KMS key ARN as the KMS_Signing_Key SHALL be used, but the interface MUST NOT assume this; the encryption key ARN SHALL be independently configurable.
5. IF `kms:Encrypt` or `kms:Decrypt` fails, THEN THE Token_Registry SHALL return a wrapped `ErrServiceUnavailable` error. THE Proxy_Core SHALL propagate this as a JSON-RPC `-32002` error to the client.
6. THE DynamoDB backend SHALL use the Cognito `sub` as the partition key and the provider name as the sort key. THE BadgerDB backend SHALL use a composite key of `{userID}:{provider}`.
7. THE Token_Registry SHALL never log or expose plaintext token values. Log entries related to token operations SHALL include only `userID`, `provider`, and operation outcome.
8. FOR ALL valid Token_Pairs, saving a Token_Pair and then retrieving it SHALL return a Token_Pair equal to the original (round-trip property).

---

### Requirement 12: OBO Proxy Pipeline

**User Story:** As an LLM agent, I want my tool calls to be forwarded to backend systems using my own downstream identity, so that audit logs and rate limits on the backend reflect my actual user account rather than a shared service account.

#### Acceptance Criteria

1. WHEN a `call_tool` request is received for a route that has `obo_provider` configured, THE OBO_Pipeline SHALL execute the following steps in order: (A) validate the inbound Cognito access token; (B) evaluate OPA policy; (C) retrieve the user's UAT from the Token_Store; (D) forward the request to the backend with `Authorization: Bearer <UAT>` and `X-Abaris-Assertion: <signed JWT>`.
2. WHEN the inbound Cognito access token is expired, THE OBO_Pipeline SHALL silently refresh the Cognito session using the stored Cognito_Refresh_Token before proceeding to step (B). THE client SHALL NOT be required to re-authenticate; Abaris manages the Cognito session lifecycle.
3. IF the Cognito_Refresh_Token is absent from the Token_Store or has been revoked, THEN THE OBO_Pipeline SHALL return a JSON-RPC error with code `-32001` and message `"session expired: re-authentication required"` to the client.
4. WHEN step (C) finds no UAT for the user+provider combination, THE OBO_Pipeline SHALL return a JSON-RPC error with code `-32001` and message `"not connected: use /connect/{provider} to authorize"` to the client.
5. WHEN the backend returns HTTP 401 in response to a forwarded request, THE Refresh_Transport SHALL use the stored Refresh_Token to exchange for a new UAT via the Secondary_Provider's token endpoint, update the Token_Store with the new Token_Pair, and retry the original request exactly once with the new UAT.
6. IF the downstream refresh exchange fails (e.g. refresh token revoked, provider unreachable), THEN THE Refresh_Transport SHALL return a wrapped `ErrServiceUnavailable` error and THE OBO_Pipeline SHALL return a JSON-RPC `-32002` error to the client. THE stale Token_Pair SHALL be deleted from the Token_Store.
7. THE OBO_Pipeline SHALL inject `Authorization: Bearer <UAT>` as the outbound `Authorization` header. THE OBO_Pipeline SHALL also inject `X-Abaris-Assertion: <signed JWT>` containing the KMS-signed IdentityContext. The caller's raw inbound Cognito token SHALL NOT be forwarded.
8. WHEN a retry succeeds after a downstream token refresh, THE OBO_Pipeline SHALL update the Token_Store with the new Token_Pair before returning the backend response to the client.
9. THE OBO_Pipeline SHALL be activated only for routes that have `obo_provider` set in `routing.yaml`. Routes without `obo_provider` SHALL continue to use Abaris's own service credentials as before (existing behavior is preserved).

---

### Requirement 13: User Onboarding — Connect Flow

**User Story:** As an end user, I want a simple OAuth2 authorization flow to connect my downstream account (e.g. GitHub) to Abaris, so that my tool calls are attributed to my own identity on the backend system.

#### Acceptance Criteria

1. THE OBO_Proxy SHALL expose a `GET /connect/{provider}` HTTP endpoint. WHEN a request is received, THE endpoint SHALL validate the caller's inbound Cognito Bearer token, then redirect the caller to the Secondary_Provider's OAuth2 authorization URL with the configured `client_id`, `redirect_uri`, `scope`, and a `state` parameter containing a short-lived HMAC-signed token encoding the caller's UserID and provider name.
2. THE OBO_Proxy SHALL expose a `GET /connect/{provider}/callback` HTTP endpoint. WHEN the Secondary_Provider redirects the caller back with a `code` and `state` parameter, THE endpoint SHALL: (a) verify the `state` HMAC signature and extract the UserID and provider; (b) exchange the `code` for a Token_Pair via the Secondary_Provider's token endpoint; (c) encrypt and save the Token_Pair to the Token_Store; (d) return HTTP 200 with a JSON body `{"status":"connected","provider":"<name>"}`.
3. IF the `state` parameter is absent, malformed, or has an invalid HMAC signature, THEN THE callback endpoint SHALL return HTTP 400 with a JSON error body and SHALL NOT store any tokens.
4. IF the authorization code exchange fails, THEN THE callback endpoint SHALL return HTTP 502 with a JSON error body identifying the provider and SHALL NOT store any tokens.
5. THE `state` token SHALL expire after a configurable TTL (default: 10 minutes). IF the callback is received after the `state` token has expired, THEN THE callback endpoint SHALL return HTTP 400 with message `"state expired: restart the connect flow"`.
6. THE `/connect/{provider}` endpoint SHALL require a valid inbound Cognito Bearer token. IF the token is absent or invalid, THEN THE endpoint SHALL return HTTP 401.
7. THE `/connect/{provider}` and `/connect/{provider}/callback` endpoints SHALL be registered only for providers listed in `secondary_providers` in `config/identity.yaml`. IF a request is received for an unknown provider, THEN THE endpoint SHALL return HTTP 404.
8. THE Connect_Flow SHALL never log the authorization code, the exchanged access token, or the refresh token. Log entries SHALL include only the UserID, provider name, and outcome.

---

### Requirement 14: Header Injection and Assertion Token

**User Story:** As a backend MCP server operator, I want every OBO-proxied request to carry both the user's downstream token and a signed corporate identity assertion, so that I can enforce both downstream authorization and corporate audit requirements.

#### Acceptance Criteria

1. WHEN THE OBO_Pipeline forwards a request to a backend, THE Proxy_Core SHALL inject `Authorization: Bearer <UAT>` as the outbound `Authorization` header, where `<UAT>` is the user's downstream access token retrieved from the Token_Store.
2. WHEN THE OBO_Pipeline forwards a request to a backend, THE Proxy_Core SHALL inject `X-Abaris-Assertion: <signed JWT>` as an additional outbound header, where `<signed JWT>` is a KMS-signed Identity Assertion Token containing the caller's normalized IdentityContext (UserID, Email, Groups, Entitlements, Provider).
3. THE `X-Abaris-Assertion` header SHALL use the same JWT structure and KMS signing mechanism as the existing `X-Abaris-Identity` header (RS256, KMS_Signing_Key, configurable TTL). THE `X-Abaris-Identity` header SHALL continue to be sent for non-OBO routes to preserve backward compatibility.
4. THE caller's raw inbound Cognito Bearer token SHALL NOT appear in any outbound header, query parameter, or request body sent to any backend.
5. THE Proxy_Core SHALL expose a `GET /.well-known/jwks.json` endpoint (already defined in Requirement 4.7) that backends can use to validate the `X-Abaris-Assertion` JWT signature independently.
6. FOR ALL OBO-proxied requests, the `sub` claim in the `X-Abaris-Assertion` JWT SHALL equal the `IdentityContext.UserID` of the authenticated caller (the Cognito `sub`), not any downstream provider user ID.

---

### Requirement 15: Token Store Configuration

**User Story:** As a DevOps engineer, I want to select the Token_Store backend via configuration, so that I can use DynamoDB in production and a local BadgerDB instance during development without changing application code.

#### Acceptance Criteria

1. THE `config/identity.yaml` file SHALL support a `token_store` section with a required `type` field (`dynamodb` or `badger`) and backend-specific fields: for `dynamodb`, a `table_name` and `region`; for `badger`, a `data_dir` path.
2. WHEN `token_store.type` is `dynamodb`, THE Token_Registry SHALL use `aws-sdk-go-v2/service/dynamodb` with the ambient IAM role credentials. THE DynamoDB table SHALL be created externally (Abaris does not create tables); IF the table does not exist at startup, THE Proxy_Core SHALL log a fatal error and terminate.
3. WHEN `token_store.type` is `badger`, THE Token_Registry SHALL use `github.com/dgraph-io/badger/v4` with the configured `data_dir`. IF the directory does not exist or is not writable, THE Proxy_Core SHALL log a fatal error and terminate.
4. THE `token_store` section SHALL also include a `kms_encryption_key_arn` field specifying the KMS key used for token encryption. This field is required regardless of backend type. IF absent, THE Proxy_Core SHALL log a fatal error and terminate.
5. THE Token_Store backend SHALL be replaceable at the composition root without modifying any domain or OBO_Pipeline logic (hexagonal architecture constraint).
