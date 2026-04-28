# Abaris — Project Roadmap

> Identity-aware MCP Broker | Go + Hexagonal Architecture + AWS KMS + OPA-ready Config

---

## Status Legend

| Symbol | Meaning |
|--------|---------|
| `🔴 Not Started` | Work not yet begun |
| `🟡 In Progress` | Actively being worked |
| `🟢 Complete` | Done and verified |
| `⏸ Blocked` | Waiting on a dependency |
| `⚡ Optional` | Can be deferred for MVP |

---

## Milestone 0 — Developer Environment & Test Infrastructure
> Goal: All external dependencies needed for local development and end-to-end testing are running and verified before any Go code is written.

### 0.1 — AWS Cognito (Test Identity Provider)

| # | Task | Status | Notes |
|---|------|--------|-------|
| 0.1.1 | Create an AWS Cognito User Pool in your dev AWS account | 🟢 Complete | `us-east-1_rJETkEEyh` |
| 0.1.2 | Create a Cognito App Client (no client secret, OIDC flow) and note the `client_id` | 🟢 Complete | `abaris-test-idp` → client ID `6smfttkp2gbfgh4thoh5jeq9og` |
| 0.1.3 | Enable the Cognito hosted UI and configure a domain | 🟢 Complete | `us-east-1rjetkeeyh.auth.us-east-1.amazoncognito.com` |
| 0.1.4 | Create test users: `bob@example.com` (read-only), `alice@example.com` (developer), `admin@example.com` (admin) | 🟢 Complete | |
| 0.1.5 | Create Cognito Groups matching Abaris policy groups: `developers`, `read-only`, `admins` | 🔴 Not Started | `aws cognito-idp create-group --group-name developers --user-pool-id ...` |
| 0.1.6 | Assign test users to groups | 🔴 Not Started | `aws cognito-idp admin-add-user-to-group ...` |
| ~~0.1.7~~ | ~~Configure a custom `groups` claim via Pre Token Generation Lambda~~ | ~~N/A~~ | Not needed — OIDCAdapter reads `cognito:groups` directly via `groups_claim` config |
| 0.1.8 | Verify: obtain a JWT for `bob@example.com` and confirm `cognito:groups: ["read-only"]` is present | 🔴 Not Started | `aws cognito-idp initiate-auth ...` or use the hosted UI |
| 0.1.9 | Populate `config/identity.yaml` with the real Cognito `discovery_url`, `jwks_endpoint`, `client_id`, and `audience` | 🟢 Complete | All values populated from live pool and `abaris-test-idp` client |

**Exit criteria:** A real Cognito-issued JWT for each test user can be decoded and shows the correct `groups` claim. `config/identity.yaml` points to the live Cognito endpoints.

---

### 0.2 — MCP Test Services

> Select a set of MCP backend servers covering four test dimensions: **auth scoping**, **data privacy**, **infrastructure security**, and **web safety**.

| # | Task | Status | Test Dimension | Notes |
|---|------|--------|----------------|-------|
| 0.2.1 | Stand up [GitHub MCP Server](https://github.com/github/github-mcp-server) locally or via Docker | 🔴 Not Started | Auth scoping | Tests read vs write tool enforcement (`github/get-*` vs `github/create-*`) |
| 0.2.2 | Stand up [Filesystem MCP Server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) with a sandboxed directory | 🔴 Not Started | Data privacy | Tests that `read-only` users cannot write/delete files; path traversal is blocked |
| 0.2.3 | Stand up [PostgreSQL MCP Server](https://github.com/modelcontextprotocol/servers/tree/main/src/postgres) against a local test DB | 🔴 Not Started | Data privacy | Tests that `read-only` users can only run SELECT; INSERT/UPDATE/DELETE are denied |
| 0.2.4 | Stand up [AWS MCP Server](https://github.com/awslabs/mcp) or a mock AWS tool server | 🔴 Not Started | Infrastructure security | Tests that infra tools (EC2, S3, IAM) are scoped to `admins` group only |
| 0.2.5 | Stand up [Fetch/Browser MCP Server](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch) | 🔴 Not Started | Web safety | Tests that URL fetch tools are restricted; `read-only` users cannot trigger outbound HTTP |
| 0.2.6 | Add route entries for each test service to `config/routing.yaml` | 🔴 Not Started | All | `github`, `filesystem`, `postgres`, `aws`, `fetch` prefixes |
| 0.2.7 | Add policy files for each test dimension to `config/policies/`: `developers.yaml`, `read-only.yaml`, `admins.yaml`, `infra-team.yaml` | 🔴 Not Started | All | |
| 0.2.8 | Write a test matrix document (`docs/test-matrix.md`) mapping each test user × tool × expected outcome (permit/deny) | 🔴 Not Started | All | Drives manual and automated verification |

**Exit criteria:** All five MCP servers respond to `list_tools` requests. The test matrix is populated and reviewed.

---

## Milestone 1 — Foundation
> Goal: Compilable Go module with all domain types, interfaces, errors, and the pure `DryRun` function. No infrastructure imports in the domain layer.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1.0 | Install Go & initialise `github.com/[username]/abaris` module | 🟢 Complete | `github.com/will-walsh/abaris-mcp`, Go 1.26.1 |
| 1.1 | Scaffold package tree (`cmd/`, `internal/domain/`, `internal/auth/`, `internal/proxy/`, `internal/policy/`, `internal/config/`, `config/policies/`, `policies/`) | 🟢 Complete | |
| 1.2 | Define domain types: `ToolCall`, `IdentityContext`, `PolicyDecision`, `DryRunResult`, `Config`, `IdentityConfig`, `RoutingConfig`, `PolicyFileConfig`, `AssertionConfig` | 🟢 Complete | |
| 1.3 | Define domain interfaces: `IdentityService`, `PolicyEngine`, `BackendTransport`, `IdentityAssertionMinter`, `Logger` | 🟢 Complete | |
| 1.4 | Define typed sentinel errors + JSON-RPC error code constants (`-32600`, `-32001`–`-32004`, `-32602`) | 🟢 Complete | |
| 1.5 | Implement `DryRun()` — pure function, no infrastructure imports | 🟢 Complete | |
| 1.6 | Implement `slog`-backed `Logger` adapter — JSON output, configurable level via env var, never logs tokens/secrets | 🟢 Complete | |
| ⚡ 1.7 | PBT: `DryRun` correctness (Properties 19, 20, 21) via `gopter` | ⚡ Optional | |

**Exit criteria:** `go build ./...` passes with zero errors.

---

## Milestone 2 — Configuration Layer
> Goal: Namespace-keyed `config.Loader` that mirrors OPA's `data.*` document model. `config.Data["routing"]` works. Hot reload of `policies/` via `fsnotify`.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 2.1 | Scaffold `/config/` directory: `identity.yaml`, `routing.yaml`, `policies/` | 🟢 Complete | |
| 2.2 | Implement `config.Loader` with namespace-keyed `Data map[string]any` — filename stem = namespace key (mirrors `data.routing`, `data.identity`, `data.policies.*` in OPA) | 🟢 Complete | `config.Data["routing"]` verified |
| 2.3 | Implement `Loader.Load()`: read + validate `identity.yaml` & `routing.yaml`, glob `policies/*.yaml`, deep-merge, cross-file validate, return `domain.Config` | 🟢 Complete | |
| 2.4 | Implement `deepMergePolicies()`: union `allowed_tools` + `denied_tools` for duplicate group names across files (deduplicated, stable-sorted) | 🟢 Complete | |
| 2.5 | Implement `validatePolicyRoutes()`: every policy pattern prefix must exist in `routing.yaml`; typed error identifies file + group + undefined prefix | 🟢 Complete | |
| 2.6 | Implement `Loader.Watch(ctx)` via `fsnotify`: watch `policies/`; on `*.yaml` change re-merge + re-validate; atomic swap on success; WARN + retain previous on failure | 🟢 Complete | |
| 2.7 | Generate sample config files: `config/identity.yaml` (Okta OIDC), `config/routing.yaml` (GitHub + KMS), `config/policies/developers.yaml`, `config/policies/read-only.yaml` | 🟢 Complete | |
| ⚡ 2.8 | PBT: `deepMergePolicies` union correctness (Property 25) | ⚡ Optional | |
| ⚡ 2.9 | PBT: `validatePolicyRoutes` rejects undefined prefixes (Property 26) | ⚡ Optional | |
| ⚡ 2.10 | PBT: hot reload rejection preserves previous policies (Property 27) | ⚡ Optional | |
| ⚡ 2.11 | PBT: config directory round-trip (Property 14) | ⚡ Optional | |

**Exit criteria:** `config.Loader.Load()` returns a valid `domain.Config` from the sample files. `config.Data["routing"]` is populated. `Watch()` detects a policy file change and swaps policies without restart.

---

## Milestone 3 — Federated Identity
> Goal: OIDC and SAML adapters that normalize any provider's claims into `IdentityContext`. Multi-provider dispatch. TTL cache.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 3.1 | Implement `OIDCAdapter` (`zitadel/oidc`): validate Bearer token, normalize → `IdentityContext`, TTL cache | 🟢 Complete | `internal/auth/oidc/adapter.go`; shared context keys in `internal/auth/authctx/` |
| 3.2 | Implement `SAMLAdapter` (`crewjam/saml`): validate assertion, normalize → `IdentityContext`, TTL cache | 🟢 Complete | `internal/auth/saml/adapter.go`; fetches IdP metadata at construction time |
| 3.3 | Implement `MultiProviderIdentityService`: dispatch by token issuer / assertion issuer | 🟢 Complete | `internal/auth/multi.go`; SAML by Issuer element, OIDC by `iss` claim; single-provider shortcut |
| 3.4 | Compile-time interface checks: `var _ domain.IdentityService = (*OIDCAdapter)(nil)` etc. | 🟢 Complete | All three types checked in `multi.go` |
| ⚡ 3.5 | PBT: absent credential → `ErrUnauthenticated`; OIDC/SAML validation correctness; cache idempotence (Properties 4–7) | ⚡ Optional | |

**Exit criteria:** A valid Cognito JWT resolves to a populated `IdentityContext` with correct `UserID`, `Email`, `Groups`.

---

## Milestone 4 — KMS Identity Assertion Token
> Goal: `KMSMinter` signs JWTs via `kms:Sign` — private key never leaves KMS. JWKS endpoint serves cached public key.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 4.1 | Implement `KMSMinter`: manual JWT construction (header + payload), `kms:Sign` (`RSASSA_PKCS1_V1_5_SHA_256`), assemble `header.payload.signature` | 🟢 Complete | `internal/auth/assertion/minter.go`; no `golang-jwt` — private key stays in KMS |
| 4.2 | Startup: `kms:GetPublicKey` → cache `*rsa.PublicKey`; expose `GET /.well-known/jwks.json` | 🟢 Complete | `internal/auth/assertion/jwks.go`; `JWKSHandler()` serves cached public key |
| 4.3 | Compile-time check: `var _ domain.IdentityAssertionMinter = (*KMSMinter)(nil)` | 🟢 Complete | `internal/auth/assertion/minter.go` |
| ⚡ 4.4 | PBT: token claims completeness, TTL invariant, no private key in memory (Properties 22–24) | ⚡ Optional | `internal/auth/assertion/minter_property_test.go` |
| ⚡ 4.5 | Unit tests: mock KMS client — JWT construction, claim values, error propagation | ⚡ Optional | `internal/auth/assertion/minter_test.go` |

**Exit criteria:** `KMSMinter.Mint()` returns a valid compact JWT. Signature verifies against the public key from `/.well-known/jwks.json`.

---

## Milestone 5 — OPA Policy Engine
> Goal: `OPAPolicyAdapter` evaluates Rego policies. Deny-by-default. `FilterTools` for Discovery. Bundle hot-reload.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 5.1 | Write base Rego bundle (`policies/`): `package abaris.authz`, group-based allow, read-only deny, deny-by-default | 🟢 Complete | `policies/abaris.rego`; deny-by-default, read-only deny, matched_rule, deny_reason |
| 5.2 | Implement `OPAPolicyAdapter`: load bundle, prepare `data.abaris.authz.allow` query, return `PolicyDecision` with `MatchedRuleID` | 🟢 Complete | `internal/policy/opa_adapter.go` |
| 5.3 | Implement `FilterTools()` on `OPAPolicyAdapter` for Discovery flow | 🟢 Complete | `internal/policy/opa_adapter.go` |
| 5.4 | OPA bundle hot-reload: poll interval, atomic `PreparedEvalQuery` swap under `sync.RWMutex` | 🟢 Complete | `StartHotReload()` + `UpdatePolicies()` in `opa_adapter.go` |
| 5.5 | Compile-time check: `var _ domain.PolicyEngine = (*OPAPolicyAdapter)(nil)` | 🟢 Complete | `internal/policy/opa_adapter.go` |
| ⚡ 5.6 | PBT: read-only deny, deny-by-default, rule ID always present, Discovery subset invariant (Properties 8–12) | ⚡ Optional | `internal/policy/opa_adapter_property_test.go` |

**Exit criteria:** `OPAPolicyAdapter.Evaluate()` denies a WRITE tool call for a `read-only` identity. `FilterTools()` returns only permitted tools.

---

## Milestone 6 — MCP Broker Core
> Goal: End-to-end request flow. Discovery filters tools by identity. Execution routes with dual-credential forwarding (`service creds` + `X-Abaris-Identity`). Raw caller token never forwarded.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 6.1 | MCP JSON-RPC 2.0 request parsing + error response construction (`-32600` for malformed) | 🟢 Complete | `internal/proxy/jsonrpc.go`; `ParseToolCall`, `ErrorResponse`, `SuccessResponse` |
| 6.2 | Implement `Broker` struct: wire all domain interfaces, no concrete infrastructure types | 🟢 Complete | `internal/proxy/broker.go` |
| 6.3 | Discovery flow (`list_tools`): aggregate backends → `FilterTools` → return reduced list | 🟢 Complete | `handleDiscovery` + `aggregateTools` in `broker.go` |
| 6.4 | Execution flow (`call_tool`): resolve identity → evaluate policy → mint IAT → forward with service creds + `X-Abaris-Identity` | 🟢 Complete | `handleExecution` + `handleStandard` in `broker.go`; OBO stub in `handleOBO` |
| 6.5 | SSE transport adapter: bind to `PORT` env var | 🟢 Complete | `internal/proxy/sse_transport.go`; `HTTPBackendTransport` also implemented |
| 6.6 | Stdio transport adapter | 🟢 Complete | `internal/proxy/stdio_transport.go` |
| 6.7 | Structured log emission: `request_id`, `caller_user_id`, `tool_name`, `transport_type`, `decision_outcome`, `matched_rule_id` | 🟢 Complete | `logToolCall` + `logPolicyDecision` in `broker.go` |
| ⚡ 6.8 | PBT: parsing round-trip, `-32600`, pass-through identity, deny → no forwarding, raw credential isolation, log field completeness, no secrets in logs (Properties 1–3, 9, 13, 16–18) | ⚡ Optional | `internal/proxy/broker_property_test.go` |

**Exit criteria:** A valid `call_tool` request from Bob (developer, Cognito OIDC) reaches the GitHub MCP backend with `X-Abaris-Identity` header. A `call_tool` for a WRITE tool from a `read-only` identity returns `-32004` and never contacts the backend.

---

## Milestone 7 — AWS Infrastructure
> Goal: Secrets Manager adapter, KMS permission validation, `/health` endpoint, graceful shutdown.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 7.1 | AWS Secrets Manager adapter: retrieve service credentials + IdP secrets at startup; env vars for region + ARNs; ambient IAM role | 🟢 Complete | `internal/infra/secrets.go`; `MustLoadSecrets` for startup fail-fast |
| 7.2 | Startup fail-fast: Secrets Manager unreachable or missing secret → fatal log + non-zero exit | 🟢 Complete | `MustGetSecret` calls `os.Exit(1)` on any failure |
| 7.3 | Startup KMS validation: `kms:DescribeKey` → verify key spec/usage; missing `kms:Sign` → fatal exit | 🟢 Complete | `KMSClient.DescribeKey` interface in `internal/auth/assertion/minter.go` |
| 7.4 | `GET /health`: HTTP 200 when ready; HTTP 503 + JSON body identifying degraded dependency | 🟢 Complete | `internal/infra/health.go`; `HealthChecker` with concurrent dependency checks |
| 7.5 | Graceful shutdown: `SIGTERM`/`SIGINT` → drain in-flight requests → exit; all logs to stdout | 🟢 Complete | `internal/infra/shutdown.go`; `RunWithGracefulShutdown` with configurable drain timeout |

**Exit criteria:** `GET /health` returns 200 in a healthy deployment. Process exits cleanly on `SIGTERM` with no dropped in-flight requests.

---

## Milestone 8 — Test Coverage
> Goal: All 27 correctness properties covered by `gopter` PBT. All adapters have unit tests. Compile-time interface checks in place.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 8.1 | Ensure all 27 `gopter` property tests exist (≥ 100 iterations each, annotated with property # and requirement) | 🔴 Not Started | Properties 1–27 |
| ⚡ 8.2 | Unit tests: OIDC/SAML error mapping, config validation, JSON-RPC error codes | ⚡ Optional | |
| ⚡ 8.3 | Unit tests: `KMSMinter` with mock KMS client | ⚡ Optional | |
| 8.4 | Compile-time interface satisfaction checks for all four adapters | 🔴 Not Started | |

**Exit criteria:** `go test ./...` passes. All 27 properties green.

---

## Milestone 9 — Integration & Smoke Tests
> Goal: End-to-end tests against real or LocalStack AWS. Smoke tests for build, config load, log format.

| # | Task | Status | Notes |
|---|------|--------|-------|
| ⚡ 9.1 | Integration: SSE + Stdio transport acceptance (`//go:build integration`) | ⚡ Optional | |
| ⚡ 9.2 | Integration: OIDC adapter end-to-end with test provider | ⚡ Optional | |
| ⚡ 9.3 | Integration: SAML adapter end-to-end with test IdP | ⚡ Optional | |
| ⚡ 9.4 | Integration: KMS signing end-to-end against LocalStack — JWT signature verifies against `kms:GetPublicKey` | ⚡ Optional | |
| ⚡ 9.5 | Integration: OPA bundle loading + hot-reload | ⚡ Optional | |
| ⚡ 9.6 | Integration: `/health` + graceful shutdown under `SIGTERM` | ⚡ Optional | |
| ⚡ 9.7 | Smoke: `go build`, config fixture loads, slog JSON format, log level env var, `go vet`/`staticcheck` | ⚡ Optional | |

**Exit criteria:** `go test -tags integration ./...` passes against LocalStack.

---

## Milestone 10 — AWS Deployment
> Goal: Production-ready Dockerfile, IAM policy, CloudWatch config, composition root wiring everything together.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 10.1 | `Dockerfile`: multi-stage build (Go builder → minimal runtime), copy binary + `/config/`, expose `PORT` | 🔴 Not Started | |
| 10.2 | IAM policy JSON: `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` on signing key ARN | 🔴 Not Started | Least-privilege |
| 10.3 | CloudWatch log group config (CDK/CloudFormation or `aws logs` CLI) | 🔴 Not Started | |
| 10.4 | Production sample config files (all sections populated, deployment-ready) | 🔴 Not Started | |
| 10.5 | `cmd/abaris/main.go` composition root: `config.Loader` → secrets → wire all adapters → start transports → register `/health` + `/.well-known/jwks.json` → block on signals | 🔴 Not Started | Final wiring |

**Exit criteria:** `docker build` succeeds. Container starts on App Runner, passes health check, and processes a `list_tools` request end-to-end.

---

## Dependency Graph

```
M0 (Dev Environment)
  ├── 0.1 Cognito ─────────────────────────────────────────── M3 (Federated Identity)
  └── 0.2 MCP Test Services ──────────────────────────────── M9 (Integration Tests)

M1 (Foundation)
  └── M2 (Config Layer)
        ├── M3 (Federated Identity) ←── 0.1 Cognito
        │     └── M4 (KMS Token)
        │           └── M6 (Broker Core) ←── M5 (OPA Engine)
        │                 └── M7 (AWS Infra)
        │                       └── M8 (Tests)
        │                             └── M9 (Integration Tests) ←── 0.2 MCP Services
        │                                   └── M10 (Deployment)
        └── M5 (OPA Engine)

M11 (OBO Proxy) ←── M6 (Broker Core) + M7 (AWS Infra)
  Requires: Token Store (DynamoDB/BadgerDB + KMS), Connect Flow, RefreshTransport
```

M0 runs in parallel with M1–M2. Cognito User Pool must be ready before M3. MCP test services must be ready before M9.

---

## MVP Scope (skip all ⚡ Optional items)

To reach a deployable MVP, complete only the non-optional tasks across all milestones. That gives you:
- Cognito test users and groups configured
- GitHub + Filesystem MCP servers for auth scoping and data privacy testing
- Namespace-keyed config loader with hot reload
- OIDC + SAML identity normalization
- KMS-signed Identity Assertion Tokens
- OPA policy enforcement with deny-by-default
- MCP Discovery + Execution broker flows
- AWS Secrets Manager + health check + graceful shutdown
- Dockerfile + IAM policy + App Runner deployment

Estimated non-optional task count: **57 tasks** across 11 milestones (including M0).

---

## Milestone 11 — OBO (On-Behalf-Of) Proxy
> Goal: Stateful per-user downstream token management. Instead of Abaris's own service credentials, OBO routes acquire and inject per-user UATs so backends receive requests attributed to the actual end-user.

### 11.1 — Multi-IdP Configuration

| # | Task | Status | Notes |
|---|------|--------|-------|
| 11.1.1 | Extend `config/identity.yaml` schema: add `secondary_providers` section with `name`, `type: oauth2`, `auth_url`, `token_url`, `client_id`, `client_secret_arn`, `scopes` | 🔴 Not Started | |
| 11.1.2 | `config.Loader`: retrieve `client_secret` for each secondary provider from Secrets Manager at startup | 🔴 Not Started | |
| 11.1.3 | Validate secondary provider entries: unique name, valid URLs, non-empty client ID + ARN, ≥1 scope | 🔴 Not Started | Fatal on failure |
| 11.1.4 | Treat `secondary_providers` as immutable at runtime (no hot reload) | 🔴 Not Started | |

### 11.2 — Token Store

| # | Task | Status | Notes |
|---|------|--------|-------|
| 11.2.1 | Define `TokenStore` interface: `Get`, `Save`, `Delete` per user per provider | 🔴 Not Started | `internal/auth/registry.go` |
| 11.2.2 | Implement `EncryptedTokenStore`: KMS envelope encryption (AES-256-GCM via `kms:GenerateDataKey` / `kms:Decrypt`) wrapping DynamoDB or BadgerDB backend | 🔴 Not Started | |
| 11.2.3 | Implement `DynamoDBTokenStore` backend (production) | 🔴 Not Started | |
| 11.2.4 | Implement `BadgerTokenStore` backend (local dev) | 🔴 Not Started | |
| 11.2.5 | Select backend via config (`token_store.type: dynamodb | badger`) | 🔴 Not Started | |

### 11.3 — Connect Flow

| # | Task | Status | Notes |
|---|------|--------|-------|
| 11.3.1 | Implement `GET /connect/{provider}` — initiates OAuth2 authorization code flow for a secondary provider | 🔴 Not Started | |
| 11.3.2 | Implement `GET /connect/{provider}/callback` — exchanges code for token pair, encrypts and stores in Token Store | 🔴 Not Started | |
| 11.3.3 | Return actionable `-32001` error when a UAT is missing: `"not connected: use /connect/{provider} to authorize"` | 🔴 Not Started | |

### 11.4 — OBO Pipeline

| # | Task | Status | Notes |
|---|------|--------|-------|
| 11.4.1 | Extend `RouteEntry` with optional `obo_provider` field | 🔴 Not Started | Empty = standard route |
| 11.4.2 | Implement `OBOPipeline`: (A) Cognito authn + silent refresh → (B) OPA authz → (C) UAT retrieval → (D) forward with `Authorization: Bearer <UAT>` + `X-Abaris-Assertion` | 🔴 Not Started | |
| 11.4.3 | Implement `RefreshTransport`: `http.RoundTripper` wrapper — on HTTP 401 from backend, refresh UAT once and retry | 🔴 Not Started | `internal/proxy/refresh_transport.go` |
| 11.4.4 | Silent Cognito refresh: on expired Cognito token, use stored refresh token to obtain new token pair silently | 🔴 Not Started | |
| 11.4.5 | Rename outbound header to `X-Abaris-Assertion` for OBO routes; support both `X-Abaris-Identity` and `X-Abaris-Assertion` during migration | 🔴 Not Started | |

### 11.5 — OBO Tests

| # | Task | Status | Notes |
|---|------|--------|-------|
| ⚡ 11.5.1 | PBT: Token Store encrypt/decrypt round-trip; UAT not found → correct error; refresh idempotence | ⚡ Optional | |
| ⚡ 11.5.2 | Unit tests: Connect flow state parameter validation, callback token exchange, error paths | ⚡ Optional | |
| ⚡ 11.5.3 | Integration: OBO pipeline end-to-end with mock secondary provider | ⚡ Optional | |

**Exit criteria:** A `call_tool` for a GitHub OBO route retrieves the user's UAT from the encrypted Token Store and forwards with `Authorization: Bearer <UAT>` + `X-Abaris-Assertion`. On 401 from the backend, the UAT is refreshed once and the request is retried transparently.

---

## Backlog / Future Enhancements

| Item | Notes |
|------|-------|
| Revisit DynamoDB key naming (PK/SK vs user_id/provider) | Current table uses generic `PK`/`SK` keys; consider migrating to semantic names `user_id`/`provider` for clarity, or document the generic key convention explicitly in the data layer |
| Full OPA migration | Config namespace model (`config.Data["routing"]`) makes this a lift-and-shift — Rego policies can reference `data.routing` directly |
| `abaris dryrun` CLI command | Pure function already implemented in M1 — just needs a CLI wrapper |
| Policy CI validation pipeline | Run `abaris dryrun` against fixture identities on every PR to the policies repo |
| Multi-region KMS key replication | Use KMS multi-region keys (`mrk-*`) for cross-region deployments |
| Metrics / OpenTelemetry | Add `otel` spans to broker flows for distributed tracing |
| Admin API (read-only) | `GET /config` endpoint returning current active config snapshot |
| SAML SP metadata endpoint | `GET /saml/metadata` for IdP registration |

---

*Last updated: README, .gitignore, and OBO Proxy milestone (M11) added; Milestones 1–7 complete*
