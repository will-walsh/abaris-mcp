# Abaris

Identity-aware MCP (Model Context Protocol) Broker written in Go. Abaris sits between AI/LLM clients and your backend MCP tool servers, enforcing federated identity validation and group-based access control on every request before anything reaches a backend.

## What it does

- Validates inbound credentials (OIDC Bearer tokens or SAML 2.0 assertions) against your configured Identity Providers
- Normalizes claims into an internal `IdentityContext` — no provider-specific types leak into the core
- Enforces OPA Rego policies: deny-by-default, group-scoped tool allow/deny lists
- Filters `tools/list` (Discovery) responses so callers only see tools they're permitted to invoke
- Routes `tools/call` (Execution) requests to the correct backend using Abaris's own service credentials — the caller's raw token is never forwarded
- Mints a short-lived KMS-signed `X-Abaris-Identity` JWT for every backend request, carrying the normalized caller identity (private key never leaves KMS)
- Hot-reloads policy files from `config/policies/` without a restart
- Supports both standard HTTP and MCP Streamable HTTP (spec 2025-03-26) backend transports — set `transport: sse` on any route to use Streamable HTTP (required for e.g. `api.githubcopilot.com/mcp/`)

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
.env/dev/                   # CloudFormation stacks (deploy in order)
```

## Configuration

Configuration is split across three file types in `/config/`. This is intentional — see [GitOps](#gitops) below.

**`config/identity.yaml`** — which Identity Providers to trust (requires restart to change):
```yaml
identity_providers:
  - name: cognito-oidc
    type: oidc
    discovery_url: https://cognito-idp.REGION.amazonaws.com/POOL_ID/.well-known/openid-configuration
    jwks_endpoint: https://cognito-idp.REGION.amazonaws.com/POOL_ID/.well-known/jwks.json
    client_id: YOUR_APP_CLIENT_ID
    audience: YOUR_APP_CLIENT_ID
    groups_claim: "cognito:groups"
```

**`config/routing.yaml`** — route table and assertion token config (requires restart to change):
```yaml
routes:
  - prefix: github
    backend_uri: https://api.githubcopilot.com/mcp/
    obo_provider: github
    transport: sse        # required for MCP Streamable HTTP backends

  - prefix: internal
    backend_uri: http://internal-mcp-server:8080
    # transport omitted = standard HTTP POST

assertion:
  issuer: https://YOUR_ALB_DNS
  audience: https://YOUR_ALB_DNS
  ttl: 60s
  kms_key_arn: arn:aws:kms:REGION:ACCOUNT_ID:key/YOUR_RSA_KEY_ID
  signing_key_id: abaris-signing-key-v1
```

The `transport: sse` field selects the MCP Streamable HTTP transport (a single POST with
`Accept: application/json, text/event-stream`). Omit it for backends that accept plain
JSON-RPC POST requests.

**`config/policies/*.yaml`** — one file per team or policy set (hot-reloaded, no restart needed):
```yaml
policies:
  - group: developers
    reduced_scope:
      allowed_tools:
        - "github/*"
        - "internal/*"
  - group: read-only
    reduced_scope:
      allowed_tools:
        - "github/get-*"
        - "github/list-*"
      denied_tools:
        - "github/delete-*"
```

When multiple policy files define entries for the same group, `allowed_tools` and `denied_tools`
are **unioned** (not replaced). Adding a new file can only expand permissions; removing
permissions requires editing existing files.

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
- `AWS_REGION` — AWS region
- `PORT` — port for the SSE transport listener (default `8080`)

## Dry run

```bash
abaris dryrun --user alice --groups developers --tool github/create-pr
```

---

## Deployment

### Prerequisites

- AWS CLI configured with sufficient permissions
- Docker
- A GitHub OAuth App (for the OBO/GitHub Copilot route)
- A CodeStar Connections GitHub connection in `AVAILABLE` status

### Stack deployment order

The stacks in `.env/dev/` must be deployed in this order. Each stack exports values
consumed by the next via `!ImportValue`.

```
01-core           VPC, subnets, NAT gateways
02-network-security  Security groups, WAF
03-data           KMS vault key, DynamoDB token table
04-compute        KMS RSA signing key, ECR, ECS cluster, IAM roles
05-pipeline       CodePipeline, CodeBuild, S3 artifact bucket
06-application    ALB, target group, listener, WAF association
07-policy         OPA bundle S3 bucket, bundle packager CodeBuild project
06b-service       ECS task definition + ECS service  ← redeploy on every release
```

Deploy each stack:
```bash
aws cloudformation deploy \
  --template-file .env/dev/01-core.yaml \
  --stack-name abaris-core \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation deploy \
  --template-file .env/dev/02-network-security.yaml \
  --stack-name abaris-netsec \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation deploy \
  --template-file .env/dev/03-data.yaml \
  --stack-name abaris-data \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation deploy \
  --template-file .env/dev/04-compute.yaml \
  --stack-name abaris-compute \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation deploy \
  --template-file .env/dev/05-pipeline.yaml \
  --stack-name abaris-pipeline \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides GitHubConnectionArn=arn:aws:codestar-connections:REGION:ACCOUNT_ID:connection/YOUR_CONNECTION_ID

aws cloudformation deploy \
  --template-file .env/dev/06-application.yaml \
  --stack-name abaris-app \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation deploy \
  --template-file .env/dev/07-policy.yaml \
  --stack-name abaris-policy \
  --capabilities CAPABILITY_NAMED_IAM

aws cloudformation deploy \
  --template-file .env/dev/06b-service.yaml \
  --stack-name abaris-service \
  --capabilities CAPABILITY_NAMED_IAM
```

### After deploying: update config files with real values

Several values are only known after the stacks are deployed. You must update the config
files before the first push triggers a build.

**Step 1 — Get the ALB DNS name** (created by `06-application`):
```bash
aws cloudformation list-exports \
  --query "Exports[?Name=='abaris-app-ALBDNSName'].Value" \
  --output text
```
Update `config/routing.yaml` — set `assertion.issuer` and `assertion.audience` to
`http://<ALB_DNS_NAME>`.

**Step 2 — Get the RSA signing key ARN** (created by `04-compute`):
```bash
aws cloudformation list-exports \
  --query "Exports[?Name=='abaris-compute-RSASigningKeyArn'].Value" \
  --output text
```
Update `config/routing.yaml` — set `assertion.kms_key_arn` to this ARN.

**Step 3 — Get the vault encryption key ARN** (created by `03-data`):
```bash
aws cloudformation list-exports \
  --query "Exports[?Name=='abaris-data-VaultEncryptionKeyArn'].Value" \
  --output text
```
Update `config/identity.yaml` — set `token_store.kms_encryption_key_arn` to this ARN.

**Step 4 — Get the Cognito User Pool ID and App Client ID**:

These come from your Cognito User Pool (created separately or via the console).
Update `config/identity.yaml`:
- `identity_providers[0].discovery_url`
- `identity_providers[0].jwks_endpoint`
- `identity_providers[0].client_id`
- `identity_providers[0].audience`

**Step 5 — Store the GitHub OAuth App client secret in Secrets Manager**:

Create a GitHub OAuth App at https://github.com/settings/developers. Set the
callback URL to `http://<ALB_DNS_NAME>/connect/github/callback`.

Store the client secret:
```bash
aws secretsmanager create-secret \
  --name abaris/github-client-secret \
  --secret-string "YOUR_GITHUB_CLIENT_SECRET"
```

Update `config/identity.yaml` — set `secondary_providers[0].client_secret_arn` to the
ARN returned above, and set `secondary_providers[0].client_id` to your GitHub OAuth App
client ID.

**Step 6 — Store the state signing key in Secrets Manager**:

This is a random secret used to sign OAuth state parameters (CSRF protection):
```bash
aws secretsmanager create-secret \
  --name abaris/state-signing-key \
  --secret-string "$(openssl rand -hex 32)"
```

The ARN is referenced automatically in `06b-service.yaml` via the `ABARIS_STATE_KEY_ARN`
environment variable — no manual update needed as long as the secret name matches.

**Step 7 — Package and upload the OPA bundle**:

Run the OPA packager CodeBuild project manually for the first deployment:
```bash
aws codebuild start-build --project-name abaris-opa-bundle-packager
```

Or build and upload locally:
```bash
curl -Lo /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x /usr/local/bin/opa
opa build -b policies/ -o bundle.tar.gz
aws s3 cp bundle.tar.gz s3://abaris-opa-bundle-$(aws sts get-caller-identity --query Account --output text)/bundle.tar.gz
```

### Deploying a new version

Push to `main` — CodePipeline picks it up automatically:
```bash
git push origin main
```

To force a redeployment without a code change (e.g. after updating config files):
```bash
aws ecs update-service \
  --cluster abaris-mcp-proxy \
  --service abaris-mcp-proxy \
  --force-new-deployment
```

To redeploy only the ECS service stack (e.g. after changing task CPU/memory):
```bash
aws cloudformation deploy \
  --template-file .env/dev/06b-service.yaml \
  --stack-name abaris-service \
  --capabilities CAPABILITY_NAMED_IAM
```

### Connecting a user to GitHub (OBO flow)

Before a user can invoke GitHub tools, they must complete the OAuth connect flow to
store their GitHub UAT in the token registry. Direct them to:

```
http://<ALB_DNS_NAME>/connect/github
```

with their Cognito Bearer token in the `Authorization` header. This redirects through
GitHub OAuth and stores the access + refresh token pair in DynamoDB. After this,
`tools/list` will include GitHub tools for that user.

### Verifying the deployment

```bash
# Health check
curl http://<ALB_DNS_NAME>/health

# JWKS endpoint (public key for backend JWT validation)
curl http://<ALB_DNS_NAME>/.well-known/jwks.json

# Tool discovery (requires a valid Cognito Bearer token)
TOKEN=$(aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id YOUR_APP_CLIENT_ID \
  --auth-parameters USERNAME=YOUR_USER,PASSWORD=YOUR_PASSWORD \
  --query "AuthenticationResult.IdToken" \
  --output text)

curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  http://<ALB_DNS_NAME>/mcp
```

### Viewing logs

```bash
# Live tail all logs
aws logs tail /ecs/abaris-mcp-proxy --follow

# Filter for errors only
aws logs tail /ecs/abaris-mcp-proxy --follow --filter-pattern "ERROR"

# Filter for a specific backend
aws logs tail /ecs/abaris-mcp-proxy --follow --filter-pattern "github"
```

### Known deployment gotchas

**`tools/list` returns `{"tools":[]}`**

Both backends are being skipped silently. Check the logs for `aggregateTools: skipping backend`.
Common causes:
- GitHub route: user has not completed the `/connect/github` OAuth flow — no UAT in the token store
- Standard routes: `ABARIS_SERVICE_CRED_<PREFIX>` environment variable not set in `06b-service.yaml`

**GitHub backend returns `invalid character 'A'` parse error**

The stored GitHub UAT is stale or was issued for the wrong scope. Re-do the connect flow:
```bash
curl -H "Authorization: Bearer $TOKEN" http://<ALB_DNS_NAME>/connect/github
```

**GitHub backend returns `405 Method Not Allowed`**

The route is missing `transport: sse` in `config/routing.yaml`. The GitHub Copilot MCP
endpoint uses MCP Streamable HTTP (spec 2025-03-26) — it does not accept a plain `GET`
to open an SSE stream. Add `transport: sse` to the route and redeploy.

**GitHub backend returns `bufio.Scanner: token too long`**

Upgrade to the current version — this was fixed by switching from `bufio.Scanner` to
`io.ReadAll` with a 32 MiB limit in `SSEBackendTransport`.

**Internal backend DNS failure (`no such host`)**

`http://internal-mcp-server:8080` is a placeholder hostname. Either deploy a real
internal MCP server and update the `backend_uri` in `config/routing.yaml`, or remove
the `internal` route entirely. The broker handles unreachable backends gracefully
(skips and continues) so this does not block other routes from working.

**OPA returns `"no policy decision produced"` for every tool (all tools filtered out)**

The `policies/` directory is missing from the Docker image. The Dockerfile must include:
```dockerfile
COPY --from=builder /build/policies /app/policies
```
Without this, the OPA engine starts with no Rego rules loaded and every evaluation returns an empty result set. Rebuild and redeploy the container after adding this line.

The secret `abaris/state-signing-key` must exist in Secrets Manager before the ECS
task starts. Create it with Step 6 above before deploying `06b-service`.

**KMS `AccessDeniedException` at startup**

The ECS task role (`AbarisECSTaskRole`) needs `kms:Sign`, `kms:GetPublicKey`, and
`kms:DescribeKey` on the RSA signing key, and `kms:GenerateDataKey` + `kms:Decrypt`
on the vault encryption key. Both are granted in `04-compute.yaml`. If you recreated
the keys outside of CloudFormation, update the ARNs in the task role policy manually.
