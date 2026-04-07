# Abaris

Identity-aware MCP (Model Context Protocol) Broker written in Go. Abaris sits between AI/LLM clients and your internal backend MCP tool servers, enforcing federated identity validation and group-based access control on every request before anything reaches a backend.

## What it does

- Validates inbound credentials (OIDC Bearer tokens or SAML 2.0 assertions) against your configured Identity Providers
- Normalizes claims into an internal `IdentityContext` — no provider-specific types leak into the core
- Enforces OPA Rego policies: deny-by-default, group-scoped tool allow/deny lists
- Filters `list_tools` (Discovery) responses so callers only see tools they're permitted to invoke
- Routes `call_tool` (Execution) requests to the correct backend using Abaris's own service credentials — the caller's raw token is never forwarded
- Mints a short-lived KMS-signed `X-Abaris-Identity` JWT for every backend request, carrying the normalized caller identity (private key never leaves KMS)
- Hot-reloads policy files from `config/policies/` without a restart

## Architecture

Hexagonal architecture — `Proxy_Core` depends only on Go interfaces. All infrastructure (OIDC, SAML, OPA, SSE/Stdio transports, AWS SDK) is wired at the composition root in `cmd/abaris/main.go`.

```
cmd/abaris/main.go          # composition root
internal/
  domain/                   # interfaces, types, DryRun — no infrastructure imports
  auth/
    oidc/                   # OIDCAdapter (zitadel/oidc)
    saml/                   # SAMLAdapter (crewjam/saml)
    assertion/              # KMSMinter — RS256 JWT via kms:Sign
  proxy/                    # Broker: Discovery + Execution flows
  policy/                   # OPAPolicyAdapter (OPA Go SDK)
  config/                   # Loader: reads /config/, deep-merges, hot-reloads
config/
  identity.yaml             # identity_providers — owned by Platform/Security
  routing.yaml              # routes + assertion config — owned by Platform/Infra
  policies/                 # *.yaml policy files — owned by individual teams
policies/                   # Rego bundle
```

## Configuration

Configuration is split across three file types in `/config/`. This is intentional — see [Architecture: Modular Config & GitOps](#gitops) below.

**`config/identity.yaml`** — which Identity Providers to trust (requires restart to change):
```yaml
identity_providers:
  - name: cognito-oidc
    type: oidc
    discovery_url: https://cognito-idp.us-east-1.amazonaws.com/<pool-id>/.well-known/openid-configuration
    jwks_endpoint: https://cognito-idp.us-east-1.amazonaws.com/<pool-id>/.well-known/jwks.json
    client_id: <client-id>
    audience: <client-id>
    groups_claim: "cognito:groups"
```

**`config/routing.yaml`** — route table and assertion token config (requires restart to change):
```yaml
routes:
  - prefix: github
    backend_uri: http://github-mcp-server:8080

assertion:
  issuer: https://abaris.example.com
  audience: https://github-mcp-server.internal
  ttl: 60s
  kms_key_arn: arn:aws:kms:us-east-1:ACCOUNT_ID:key/mrk-REPLACE
  signing_key_id: abaris-2024-01
```

**`config/policies/*.yaml`** — one file per team or policy set (hot-reloaded, no restart needed):
```yaml
policies:
  - group: developers
    reduced_scope:
      allowed_tools:
        - "github/*"
  - group: read-only
    reduced_scope:
      allowed_tools:
        - "github/get-*"
      denied_tools:
        - "github/delete-*"
```

When multiple policy files define entries for the same group, `allowed_tools` and `denied_tools` are **unioned** (not replaced). Adding a new file can only expand permissions; removing permissions requires editing existing files.

## GitOps

Policy files are designed for GitOps workflows:

1. Policy files live in a dedicated `abaris-policies` Git repo
2. PRs run `abaris dryrun` in CI to catch regressions before merge
3. On merge, a GitOps operator (Flux, ArgoCD, or a sync sidecar) copies updated `*.yaml` files into the container's `/config/policies/` via a shared volume or ConfigMap mount
4. `fsnotify` detects the change, re-merges and re-validates, and atomically swaps in the new policies — no restart, no dropped requests
5. If the new policies fail cross-file validation (e.g. referencing an undefined route prefix), the previous policies remain active and a WARN is logged

`identity.yaml` and `routing.yaml` are intentionally excluded from hot reload — changes to those files affect the security boundary and require a deliberate deployment.

## Running locally

```bash
go build ./...
go test ./...
```

Environment variables required at startup:
- `AWS_REGION` — AWS region for KMS and Secrets Manager
- `KMS_KEY_ARN` — ARN of the asymmetric signing key
- `PORT` — port for the SSE transport listener

## Dry run

The `DryRun` function in `internal/domain` is a pure function (no network calls) that simulates the policy + routing check for a given identity and tool call. Use it in CI to validate policy changes before deploying:

```bash
abaris dryrun --user alice --groups developers --tool github/create-pr
```

## Deployment

Target: AWS App Runner. The IAM role assigned to the service needs:
- `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` on the signing key ARN
- `secretsmanager:GetSecretValue` on the service credential secrets

Health check: `GET /health` → 200 when ready, 503 with JSON body when a dependency is degraded.

JWKS endpoint: `GET /.well-known/jwks.json` — serves the public key so backend servers can independently validate `X-Abaris-Identity` tokens.
