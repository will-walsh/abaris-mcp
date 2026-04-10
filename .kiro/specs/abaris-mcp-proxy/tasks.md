# Implementation Plan: Abaris MCP Proxy

## Overview

Incremental build of the Abaris identity-aware MCP Broker in Go, following Hexagonal Architecture. Each phase produces working, compilable code that builds on the previous phase. Infrastructure adapters are wired at the composition root; the domain layer has no infrastructure imports.

---

## Tasks

- [x] 1. Phase 1 — Repository & Domain Foundation
  - [x] 1.1 Initialise Go module (`github.com/[username]/abaris`) and scaffold the package tree: `cmd/abaris/`, `internal/domain/`, `internal/auth/oidc/`, `internal/auth/saml/`, `internal/auth/assertion/`, `internal/proxy/`, `internal/policy/`, `internal/config/`, `policies/`, `config/policies/`
    - _Requirements: 8.7_
  - [x] 1.2 Define all domain types in `internal/domain/`: `ToolCall`, `IdentityContext`, `PolicyDecision`, `DryRunResult`, `Config`, `IdentityConfig`, `RoutingConfig`, `PolicyFileConfig`, `IdentityProviderConfig`, `RouteEntry`, `PolicyEntry`, `ReducedScope`, `AssertionConfig`
    - _Requirements: 1.2, 2.4, 3.1, 4.6, 5.2, 5.3, 5.4_
  - [x] 1.3 Define all domain interfaces in `internal/domain/`: `IdentityService`, `PolicyEngine`, `BackendTransport`, `IdentityAssertionMinter`, `Logger`
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_
  - [x] 1.4 Define all typed sentinel errors and JSON-RPC error code constants in `internal/domain/errors.go`
    - _Requirements: 2.6, 2.7, 2.8, 3.4, 3.7, 4.8, 4.9, 1.5_
  - [x] 1.5 Implement `DryRun(cfg Config, identity IdentityContext, call ToolCall) DryRunResult` in `internal/domain/dryrun.go` — pure function, no infrastructure imports
    - _Requirements: 5.4, 4.10_
  - [x] 1.6 Implement the `slog`-backed `Logger` adapter in `internal/infra/logger.go`; support configurable log level via env var; emit JSON format; never log raw tokens or secrets
    - _Requirements: 6.1, 6.5, 6.6_
  - [x] 1.7 Write property tests for `DryRun` (Properties 19, 20, 21) using `gopter`
    - **Property 19: DryRun policy check correctness** — Validates: Requirements 5.4
    - **Property 20: DryRun routing check correctness** — Validates: Requirements 4.5, 4.6
    - **Property 21: DryRun determinism** — Validates: Requirements 5.7

- [x] 2. Phase 2 — Configuration Layer
  - [x] 2.1 Scaffold the `/config/` directory with `identity.yaml`, `routing.yaml`, and `policies/` subdirectory; define `IdentityConfig`, `RoutingConfig`, `PolicyFileConfig` partial structs in `internal/domain/`
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
  - [x] 2.2 Implement `config.Loader.Load()` in `internal/config/loader.go`: read `identity.yaml` and `routing.yaml` (validate with `github.com/go-playground/validator/v10`), glob all `*.yaml` in `policies/`, call `deepMergePolicies`, call `validatePolicyRoutes`, return merged `domain.Config`; fatal log + non-zero exit on any error
    - _Requirements: 5.1, 5.5, 5.6, 5.7_
  - [x] 2.3 Implement `deepMergePolicies(files []PolicyFileConfig) []PolicyEntry`: for duplicate group names across files, union `allowed_tools` and `denied_tools` (deduplicated, stable-sorted)
    - _Requirements: 5.4_
  - [x] 2.4 Implement `validatePolicyRoutes(policies []PolicyEntry, routes []RouteEntry) error`: for each policy pattern extract the prefix segment and verify it exists in routes; return a typed error identifying the Policy_File path, group name, and undefined prefix on failure
    - _Requirements: 5.7_
  - [x] 2.5 Implement `config.Loader.Watch(ctx context.Context) error` using `github.com/fsnotify/fsnotify`: watch the `policies/` subdirectory; on any `*.yaml` create/modify/delete event, re-read and re-merge all policy files, run `validatePolicyRoutes`; on success atomically swap active policies under `sync.RWMutex` and call `onChange`; on failure log WARN and retain previous policies
    - _Requirements: 5.8, 5.9_
  - [x] 2.6 Generate sample config files: `config/identity.yaml` (Okta OIDC provider), `config/routing.yaml` (GitHub MCP backend + KMS assertion config), `config/policies/developers.yaml` (developers group, `github/*`), `config/policies/read-only.yaml` (read-only group, `github/get-*` allowed, `github/delete-*` denied)
    - _Requirements: 5.1, 5.2, 5.3, 5.4_
  - [x] 2.7 Write property test for `deepMergePolicies` (Property 25) using `gopter`
    - **Property 25: Deep merge union correctness**
    - **Validates: Requirements 5.4**
  - [x] 2.8 Write property test for `validatePolicyRoutes` (Property 26) using `gopter`
    - **Property 26: Cross-file validation rejects undefined prefixes**
    - **Validates: Requirements 5.7**
  - [x] 2.9 Write property test for hot reload rejection (Property 27) using `gopter`
    - **Property 27: Hot reload rejection preserves previous policies**
    - **Validates: Requirements 5.9**
  - [x] 2.10 Write property test for `config.Loader.Load()` round-trip (Property 14) using `gopter`
    - **Property 14: Config directory round-trip**
    - **Validates: Requirements 5.11**
  - [x] 2.11 Write property test for invalid config always causing fatal error (Property 15) using `gopter`
    - **Property 15: Invalid config always causes fatal startup failure**
    - **Validates: Requirements 5.6**

- [x] 3. Phase 3 — Federated Identity Adapters
  - [x] 3.1 Implement `OIDCAdapter` in `internal/auth/oidc/`: validate Bearer tokens using `zitadel/oidc`, normalize claims into `IdentityContext`, add TTL cache (`github.com/jellydator/ttlcache/v3`)
    - _Requirements: 2.1, 2.2, 2.4, 2.9, 2.10_
  - [x] 3.2 Implement `SAMLAdapter` in `internal/auth/saml/`: validate SAML assertions using `crewjam/saml`, normalize attributes into `IdentityContext`, add TTL cache
    - _Requirements: 2.1, 2.3, 2.4, 2.9, 2.10_
  - [x] 3.3 Implement `MultiProviderIdentityService` in `internal/auth/`: dispatch to the correct adapter by token issuer or assertion issuer; support simultaneous multiple providers
    - _Requirements: 2.5_
  - [x] 3.4 Add compile-time interface satisfaction checks: `var _ domain.IdentityService = (*OIDCAdapter)(nil)` and `var _ domain.IdentityService = (*SAMLAdapter)(nil)`
    - _Requirements: 8.3_
  - [x] 3.5 Write property tests for identity adapters (Properties 4, 5, 6, 7) using `gopter`
    - **Property 4: Absent credential always yields ErrUnauthenticated** — Validates: Requirements 2.6
    - **Property 5: OIDC token validation correctness** — Validates: Requirements 2.2, 2.4, 2.8
    - **Property 6: SAML assertion validation correctness** — Validates: Requirements 2.3, 2.4, 2.8
    - **Property 7: Identity context cache idempotence** — Validates: Requirements 2.9

- [x] 4. Phase 4 — KMS Identity Assertion Token
  - [x] 4.1 Implement `KMSMinter` in `internal/auth/assertion/`: manually construct JWT header+payload with standard OIDC top-level claims (`iss`, `sub`, `aud`, `iat`, `exp`) and `ext_identity` object (`origin_jti`, `groups`, `entitlements`, `provider`); call `kms:Sign` (RSASSA_PKCS1_V1_5_SHA_256) for the signature; assemble `header.payload.signature`; never load private key into memory; use `github.com/aws/aws-sdk-go-v2/service/kms`
    - _Requirements: 4.4, 4.6_
  - [x] 4.2 Update `IdentityAssertionMinter.Mint` signature in `internal/domain/interfaces.go` to accept `originJTI string` alongside `IdentityContext`; update `AssertionConfig` in `internal/domain/types.go` to add `Audience string` field; update `config/routing.yaml` sample to include `audience` field
    - _Requirements: 4.6_
  - [x] 4.3 At startup, call `kms:GetPublicKey` and cache the `*rsa.PublicKey` in `KMSMinter`; expose `JWKSHandler` for `GET /.well-known/jwks.json` serving the cached public key — no per-request KMS call
    - _Requirements: 4.7, 7.2_
  - [x] 4.4 Add compile-time check: `var _ domain.IdentityAssertionMinter = (*KMSMinter)(nil)`
    - _Requirements: 8.1_
  - [x] 4.5 Write property tests for `KMSMinter` using a mock KMS client (Properties 22, 23, 24) using `gopter`
    - **Property 22: Identity Assertion Token contains all required claims** — Validates: Requirements 4.4, 4.6
    - **Property 23: Identity Assertion Token TTL invariant** — Validates: Requirements 4.6
    - **Property 24: KMS signing never exposes private key material** — Validates: Requirements 4.4, 7.2
  - [x] 4.6 Write unit tests for `KMSMinter` using a mock KMS client: correct JWT construction, `ext_identity` object shape, `aud` claim value, `origin_jti` propagation, error propagation on KMS failure
    - _Requirements: 4.4, 4.6, 7.7_

- [x] 5. Phase 5 — OPA Policy Engine
  - [x] 5.1 Write the base Rego policy bundle in `policies/`: `package abaris.authz`, `default allow = false`, group-based allow rule, `deny_reason` rule for read-only write/delete, deny-by-default for unknown operation type
    - _Requirements: 3.2, 3.3, 3.7_
  - [x] 5.2 Implement `OPAPolicyAdapter` in `internal/policy/`: load bundle via `rego.LoadBundle`, prepare `data.abaris.authz.allow` query at startup, evaluate on every `Evaluate` call, return `PolicyDecision` with `MatchedRuleID`
    - _Requirements: 3.1, 3.2, 3.8_
  - [x] 5.3 Implement `FilterTools(ctx, identityCtx, allTools)` on `OPAPolicyAdapter` for the Discovery flow — returns only tools permitted by the caller's groups
    - _Requirements: 4.1_
  - [x] 5.4 Implement OPA bundle hot-reload: poll bundle source on configurable interval, atomically swap `PreparedEvalQuery` under `sync.RWMutex`
    - _Requirements: 3.6_
  - [x] 5.5 Add compile-time check: `var _ domain.PolicyEngine = (*OPAPolicyAdapter)(nil)`
    - _Requirements: 8.5_
  - [x] 5.6 Write property tests for `OPAPolicyAdapter` (Properties 8, 9, 10, 11, 12) using `gopter`
    - **Property 8: Read-only groups are denied write/delete tools** — Validates: Requirements 3.3
    - **Property 9: Deny decisions always produce -32004 and no backend forwarding** — Validates: Requirements 3.4, 4.4
    - **Property 10: Unknown operation type defaults to deny** — Validates: Requirements 3.7
    - **Property 11: Policy decisions always carry a rule identifier** — Validates: Requirements 3.8
    - **Property 12: Discovery result is always a subset of the full tool list** — Validates: Requirements 4.1

- [x] 6. Phase 6 — MCP Broker Core
  - [x] 6.1 Implement MCP JSON-RPC 2.0 request parsing and error response construction in `internal/proxy/`: parse into `ToolCall`, return `-32600` for malformed requests
    - _Requirements: 1.2, 1.5_
  - [x] 6.2 Implement the `Broker` struct in `internal/proxy/`: wire `IdentityService`, `PolicyEngine`, `BackendTransport`, `IdentityAssertionMinter`, `Logger`; depend only on domain interfaces
    - _Requirements: 8.1, 8.6_
  - [x] 6.3 Implement the Discovery flow (`list_tools`): aggregate tool lists from all configured backends using service credentials, call `PolicyEngine.FilterTools`, return reduced list to client
    - _Requirements: 4.1, 4.3_
  - [x] 6.4 Implement the Execution flow (`call_tool`): resolve identity → evaluate policy → check `RouteEntry.OBOProvider`; if empty: retrieve service credentials → mint Identity Assertion Token (with `originJTI`) → forward with service creds + `X-Abaris-Identity`; if set: delegate to `OBOPipeline`; never forward raw caller token
    - _Requirements: 4.2, 4.3, 4.4, 4.5, 4.8, 4.9, 4.10, 12.1, 12.9_
  - [x] 6.5 Implement SSE transport adapter: bind to `PORT` env var, accept inbound MCP requests over SSE, forward backend responses unmodified
    - _Requirements: 1.1, 1.4, 9.5_
  - [x] 6.6 Implement Stdio transport adapter: accept inbound MCP requests over Stdio, forward backend responses unmodified
    - _Requirements: 1.1, 1.4_
  - [x] 6.7 Implement structured log emission in `Broker`: log on every `ToolCall` received (request_id, caller_user_id, tool_name, transport_type, timestamp) and on every policy decision (request_id, caller_user_id, tool_name, decision_outcome, matched_rule_id)
    - _Requirements: 6.2, 6.3, 6.4_
  - [x] 6.8 Write property tests for `Broker` core flows (Properties 1, 2, 3, 9, 13, 16, 17, 18) using `gopter`
    - **Property 1: MCP request parsing round-trip** — Validates: Requirements 1.2, 1.3
    - **Property 2: Invalid requests always produce -32600** — Validates: Requirements 1.5
    - **Property 3: Backend response pass-through identity** — Validates: Requirements 1.4
    - **Property 9: Deny decisions always produce -32004 and no backend forwarding** — Validates: Requirements 3.4, 4.4
    - **Property 13: Raw credential never forwarded to backends** — Validates: Requirements 4.5
    - **Property 16: Log entries for tool calls contain all required fields** — Validates: Requirements 6.2
    - **Property 17: Log entries for policy decisions contain all required fields** — Validates: Requirements 6.3
    - **Property 18: Sensitive values never appear in log output** — Validates: Requirements 6.6

- [x] 7. Checkpoint — Ensure all unit and property tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Phase 7 — AWS Infrastructure Adapters
  - [x] 8.1 Implement AWS Secrets Manager adapter: retrieve `Service_Credentials` and Identity Provider client secrets at startup using `aws-sdk-go-v2/service/secretsmanager`; accept region and secret ARNs from env vars with no defaults; use ambient IAM role credentials
    - _Requirements: 7.1, 7.5, 7.6_
  - [x] 8.2 Add startup fail-fast checks for Secrets Manager: unreachable → fatal log + non-zero exit; missing secret → fatal log identifying key + non-zero exit
    - _Requirements: 7.3, 7.4_
  - [x] 8.3 Add startup KMS permission validation: call `kms:DescribeKey` to verify key exists and has expected spec/usage; if unreachable or `kms:Sign` permission absent → fatal log + non-zero exit
    - _Requirements: 7.7, 9.6_
  - [x] 8.4 Implement `GET /health` endpoint: return HTTP 200 when ready; return HTTP 503 with JSON body identifying degraded dependency when a required dependency is unavailable
    - _Requirements: 9.1, 9.2_
  - [x] 8.5 Implement graceful shutdown: handle `SIGTERM` and `SIGINT`, drain in-flight requests within configurable timeout, then exit cleanly; emit all log output to stdout
    - _Requirements: 9.3, 9.4_

- [x] 9. Phase 8 — Property-Based & Unit Tests
  - [x] 9.1 Ensure all 36 correctness properties have a corresponding `gopter` property test (Properties 1–36); each test runs ≥ 100 iterations and is annotated with its property number and requirements clause
    - _Requirements: 8.6_
  - [x] 9.2 Write unit tests for all adapters: OIDC HTTP error mapping (Req 2.7), SAML parse error mapping, config validation (missing fields, invalid URLs, unrecognised provider type), JSON-RPC error code mappings
    - _Requirements: 2.7, 5.6, 1.5_
  - [x] 9.3 Write mock KMS client unit tests for `KMSMinter`: correct JWT construction, claim values, error propagation on KMS failure, no private key in memory
    - _Requirements: 4.4, 7.2_
  - [x] 9.4 Add compile-time interface satisfaction checks for all adapters: `OIDCAdapter`, `SAMLAdapter`, `OPAPolicyAdapter`, `KMSMinter`
    - _Requirements: 8.3, 8.5_

- [x] 10. Phase 9 — Integration & Smoke Tests
  - [x] 10.1 Write integration tests (build tag `integration`) for SSE and Stdio transport acceptance
    - _Requirements: 1.1_
  - [x] 10.2 Write integration tests for OIDC adapter end-to-end with a test OIDC provider
    - _Requirements: 2.2, 2.4_
  - [x] 10.3 Write integration tests for SAML adapter end-to-end with a test IdP
    - _Requirements: 2.3, 2.4_
  - [x] 10.4 Write integration tests for KMS signing end-to-end against LocalStack: verify produced JWT signature validates against the public key from `kms:GetPublicKey`
    - _Requirements: 4.4, 7.2_
  - [x] 10.5 Write integration tests for OPA bundle loading and hot-reload
    - _Requirements: 3.2, 3.6_
  - [x] 10.6 Write integration tests for health check endpoint and graceful shutdown under SIGTERM
    - _Requirements: 9.1, 9.2, 9.4_
  - [x] 10.7 Write smoke tests: `go build` succeeds, valid Config_Directory fixture loads without error, slog JSON output format, log level env var respected, `go vet` / `staticcheck` pass
    - _Requirements: 5.1, 6.1, 6.5_

- [x] 11. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Phase 11 — OBO Proxy (Stateful On-Behalf-Of)
  - [x] 12.1 Add `TokenPair`, `TokenStoreConfig`, `SecondaryProviderConfig` types to `internal/domain/types.go`; add `OBOProvider string` field to `RouteEntry`; add `TokenStore` interface to `internal/domain/interfaces.go`; add `ErrNotConnected` sentinel error to `internal/domain/errors.go`
    - _Requirements: 11.1, 10.1, 12.4_
  - [x] 12.2 Implement `EncryptedTokenStore` wrapper in `internal/auth/registry.go`: KMS envelope encryption using `kms:GenerateDataKey` on Save and `kms:Decrypt` on Get; define `KMSClient` interface for testability; add compile-time checks `var _ domain.TokenStore = (*EncryptedTokenStore)(nil)`
    - _Requirements: 11.3, 11.4, 11.5_
  - [x] 12.3 Implement `DynamoDBTokenStore` in `internal/auth/registry_dynamo.go`: partition key `user_id`, sort key `provider`; define `DynamoDBClient` interface; add compile-time check `var _ domain.TokenStore = (*DynamoDBTokenStore)(nil)`
    - _Requirements: 11.6, 15.2_
  - [x] 12.4 Implement `BadgerTokenStore` in `internal/auth/registry_badger.go`: composite key `{userID}:{provider}`; add compile-time check `var _ domain.TokenStore = (*BadgerTokenStore)(nil)`
    - _Requirements: 11.6, 15.3_
  - [x] 12.5 Extend `config.Loader` to parse `secondary_providers` and `token_store` sections from `config/identity.yaml`; resolve each `client_secret_arn` from Secrets Manager at startup; fatal log + non-zero exit on any missing secret or invalid config
    - _Requirements: 10.1, 10.2, 10.3, 15.1, 15.4_
  - [x] 12.6 Implement `OBOPipeline` in `internal/proxy/obo_pipeline.go`: Step A (Cognito authn + silent refresh via stored Cognito refresh token) → Step B (OPA authz) → Step C (UAT retrieval from TokenStore; return `-32001` if absent) → Step D (forward via `RefreshTransport` with `Authorization: Bearer <UAT>` + `X-Abaris-Assertion`)
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 14.1, 14.2_
  - [x] 12.7 Implement `RefreshTransport` in `internal/proxy/refresh_transport.go`: wraps `http.RoundTripper`; on HTTP 401 calls `TokenRefresher.Refresh` exactly once, saves new `TokenPair` to `TokenStore`, retries with new access token; deletes stale pair and returns `ErrServiceUnavailable` if refresh fails; add compile-time check `var _ http.RoundTripper = (*RefreshTransport)(nil)`
    - _Requirements: 12.5, 12.6, 12.8_
  - [x] 12.8 Implement `OAuth2TokenRefresher` in `internal/proxy/refresh_transport.go`: exchanges stored refresh token with Secondary_Provider token endpoint using `golang.org/x/oauth2`; add compile-time check `var _ TokenRefresher = (*OAuth2TokenRefresher)(nil)`
    - _Requirements: 12.5_
  - [x] 12.9 Implement `ConnectHandler` in `internal/proxy/connect_handler.go`: `GET /connect/{provider}` validates Cognito token → mints HMAC-SHA256 state token (key from Secrets Manager) → redirects to OAuth2 auth URL; `GET /connect/{provider}/callback` verifies state → exchanges code → saves encrypted `TokenPair`; return 404 for unknown providers, 401 for missing Cognito token, 400 for invalid/expired state, 502 for failed code exchange
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6, 13.7_
  - [x] 12.10 Update `Broker` in `internal/proxy/` to dispatch `call_tool` to `OBOPipeline` when `RouteEntry.OBOProvider` is non-empty; standard service-credentials path unchanged for routes without `obo_provider`
    - _Requirements: 12.9_
  - [x] 12.11 Write property tests for OBO components (Properties 28–36) using `gopter`
    - **Property 28: TokenStore round-trip with encryption verification** — Validates: Requirements 11.3, 11.8
    - **Property 29: Secondary provider config validation rejects all invalid inputs** — Validates: Requirements 10.3
    - **Property 30: OBO pipeline header injection and Cognito token exclusion** — Validates: Requirements 12.7, 14.1, 14.2, 14.4
    - **Property 31: Refresh transport retries exactly once on 401** — Validates: Requirements 12.5
    - **Property 32: Connect flow state token expiry** — Validates: Requirements 13.5
    - **Property 33: Invalid or tampered state always yields HTTP 400** — Validates: Requirements 13.3
    - **Property 34: OBO pipeline activated only for routes with obo_provider** — Validates: Requirements 12.9
    - **Property 35: X-Abaris-Assertion sub claim equals IdentityContext.UserID** — Validates: Requirements 14.6
    - **Property 36: Token operations never log plaintext token values** — Validates: Requirements 11.7, 13.8
  - [x] 12.12 Write unit tests for OBO components: `EncryptedTokenStore` with mock KMS errors, `DynamoDBTokenStore` key format, `BadgerTokenStore` key format, `OBOPipeline` with no UAT → `-32001`, `OBOPipeline` with expired Cognito token + valid refresh, `ConnectHandler` with unknown provider → 404
    - _Requirements: 11.5, 11.6, 12.3, 12.4, 13.6_
  - [x] 12.13 Write integration tests for OBO components (build tag `integration`): `DynamoDBTokenStore` round-trip against LocalStack, `EncryptedTokenStore` round-trip against LocalStack KMS, `ConnectHandler` end-to-end with mock OAuth2 provider, `RefreshTransport` 401-retry against mock backend
    - _Requirements: 11.3, 13.1, 12.5_

- [x] 13. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Phase 12 — AWS Deployment
  - [x] 14.1 Write `Dockerfile`: multi-stage build (Go builder → minimal runtime image), copy binary and `/config/` directory, expose `PORT`
    - _Requirements: 9.3, 9.5_
  - [x] 14.2 Write IAM policy document (JSON) granting the App Runner service role minimum permissions: `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` (signing key); `kms:GenerateDataKey`, `kms:Decrypt` (encryption key); `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem` (token table); `secretsmanager:GetSecretValue` (scoped to `abaris/*`)
    - _Requirements: 9.6, 11.3, 15.2_
  - [x] 14.3 Write CloudWatch log group configuration (e.g., CDK/CloudFormation snippet or `aws logs` CLI commands) for App Runner log forwarding
    - _Requirements: 9.3_
  - [x] 14.4 Write production-ready sample config files (`config/identity.yaml` with `secondary_providers` and `token_store` sections, `config/routing.yaml` with `obo_provider` on OBO routes, `config/policies/developers.yaml`, `config/policies/read-only.yaml`) with all sections populated, suitable for use as a deployment template
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 10.1, 15.1_
  - [x] 14.5 Write `cmd/abaris/main.go` composition root: instantiate `config.Loader`, call `Load()`, resolve secondary provider secrets, start `Watch(ctx)` goroutine, fetch secrets, wire all adapters (SSE, Stdio, OIDCAdapter, SAMLAdapter, OPAPolicyAdapter, KMSMinter, EncryptedTokenStore, OBOPipeline, RefreshTransport, ConnectHandler, SecretsManagerAdapter, slog Logger), start transports, register `/health`, `/.well-known/jwks.json`, `/connect/{provider}`, and `/connect/{provider}/callback` handlers, block on signals
    - _Requirements: 8.7, 9.1, 9.4, 9.5, 12.1, 13.1_

- [x] 15. Final Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements for traceability
- Property tests use `github.com/leanovate/gopter` with ≥ 100 iterations per property
- Integration tests use the `//go:build integration` build tag and require LocalStack or live AWS for KMS/Secrets Manager/DynamoDB tests
- The domain layer (`internal/domain`) must never import infrastructure packages
- The composition root (`cmd/abaris/main.go`) is the only place where adapters are wired together
- OBO components (Phase 11) depend on Phase 4 (KMSMinter) and Phase 6 (Broker) being complete
- The `X-Abaris-Identity` header (standard routes) and `X-Abaris-Assertion` header (OBO routes) use the same JWT structure: standard OIDC top-level claims (`iss`, `sub`, `aud`, `iat`, `exp`) + `ext_identity` object (`origin_jti`, `groups`, `entitlements`, `provider`)
