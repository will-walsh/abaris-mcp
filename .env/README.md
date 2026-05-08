# Abaris Deployment Environments

This directory is **git-ignored** — never commit it.

```
.env/
└── dev/
    ├── 01-core.yaml          # VPC, subnets, IGW, NAT gateways, route tables, flow logs
    ├── 02-network-security.yaml  # Security groups, WAF Web ACL + logging
    ├── 03-data.yaml          # KMS vault key + DynamoDB table + stream audit Lambda
    ├── 04-compute.yaml       # KMS signing key, IAM roles, ECR, ECS cluster, log groups
    ├── 05-pipeline.yaml      # S3 artifact bucket, CodeBuild, CodePipeline
    ├── 06-application.yaml   # ALB, ECS task definition + service, WAF association
    └── 07-policy.yaml        # OPA bundle bucket, bundle packager, staleness alarm
```

## Why this structure

| Stack | Co-location rationale |
|---|---|
| `03-data` | Vault KMS key and DynamoDB table share a lifecycle — the key encrypts the table, so they deploy and destroy together. No external ARN dependency. |
| `04-compute` | RSA signing key and IAM roles are in the same stack so the key policy can reference the ECS task role ARN directly — no circular dependency, no wildcard `*` workaround. |
| `05-pipeline` | CI/CD pipeline is separated from the running service so you can update the pipeline without touching ECS, and vice versa. |
| `06-application` | The smallest, fastest-changing stack — only updated on releases. |
| `07-policy` | OPA/Rego policy changes are fully independent of application deploys. |

## Dependency chain

```
01-core
  └── 02-network-security
        ├── 03-data ──────────────────────────────┐
        │                                          │
        └── 04-compute (imports 03-data) ──────────┤
              ├── 05-pipeline                      │
              └── 06-application (imports 01,02,03,04)
                    └── 07-policy (imports 03,04)
```

---

## Pre-Steps

### 1. AWS CLI configured

```bash
aws sts get-caller-identity
```

### 2. Create the CodeStar GitHub connection

Required by `05-pipeline`. One-time OAuth handshake — must be done via the console.

1. Open [Developer Tools → Connections](https://console.aws.amazon.com/codesuite/settings/connections)
2. **Create connection** → GitHub → authorise `will-walsh/abaris-mcp`
3. Wait for status **Available**, then copy the ARN

```bash
# Retrieve the ARN later
aws codestar-connections list-connections \
  --provider-type GitHub \
  --query "Connections[*].[ConnectionName,ConnectionArn,ConnectionStatus]" \
  --output table
```

### 3. Create Secrets Manager secrets

The ECS task role has `secretsmanager:GetSecretValue` on `abaris/*`. Create secrets before the first application deploy:

```bash
aws secretsmanager create-secret \
  --name abaris/github-client-secret \
  --secret-string '{"client_secret":"YOUR_GITHUB_OAUTH_SECRET"}'

aws secretsmanager create-secret \
  --name abaris/service-credentials \
  --secret-string '{"token":"YOUR_SERVICE_TOKEN"}'
```

---

## Deploy

Set these once:

```bash
export REGION=YOUR_REGION
export GITHUB_CONNECTION_ARN=arn:aws:codestar-connections:REGION:ACCOUNT_ID:connection/YOUR_ID
```

Then deploy in order:

```bash
# 01 — Core networking
aws cloudformation deploy \
  --template-file .env/dev/01-core.yaml \
  --stack-name abaris-core \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION

# 02 — Network security
aws cloudformation deploy \
  --template-file .env/dev/02-network-security.yaml \
  --stack-name abaris-network-security \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION

# 03 — Data (vault key + DynamoDB)
aws cloudformation deploy \
  --template-file .env/dev/03-data.yaml \
  --stack-name abaris-data \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION

# 04 — Compute (signing key + IAM + ECR + ECS cluster)
aws cloudformation deploy \
  --template-file .env/dev/04-compute.yaml \
  --stack-name abaris-compute \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION

# 05 — Pipeline (CodeBuild + CodePipeline)
aws cloudformation deploy \
  --template-file .env/dev/05-pipeline.yaml \
  --stack-name abaris-pipeline \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides GitHubConnectionArn=$GITHUB_CONNECTION_ARN \
  --region $REGION

# 06 — Application (ALB only — stable, rarely changes)
aws cloudformation deploy \
  --template-file .env/dev/06-application.yaml \
  --stack-name abaris-application \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION

# 06b — Service (ECS task + service — changes on every release)
aws cloudformation deploy \
  --template-file .env/dev/06b-service.yaml \
  --stack-name abaris-service \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION

# 07 — Policy (OPA bundle bucket + packager)
aws cloudformation deploy \
  --template-file .env/dev/07-policy.yaml \
  --stack-name abaris-policy \
  --capabilities CAPABILITY_NAMED_IAM \
  --region $REGION
```

### Optional parameters for 06-application

| Parameter | Default | Description |
|---|---|---|
| `ContainerPort` | `8080` | Port the Abaris binary listens on |
| `TaskCPU` | `512` | Fargate task CPU units |
| `TaskMemory` | `1024` | Fargate task memory (MiB) |
| `DesiredCount` | `1` | Number of running ECS tasks |

---

## After Deployment

Trigger the first pipeline run (builds the Docker image and deploys to ECS):

```bash
aws codepipeline start-pipeline-execution \
  --name abaris-mcp-proxy-pipeline \
  --region $REGION
```

Package and upload the initial OPA bundle:

```bash
aws codebuild start-build \
  --project-name abaris-opa-bundle-packager \
  --region $REGION
```

Verify the service:

```bash
SERVICE_URL=$(aws cloudformation list-exports \
  --query "Exports[?Name=='abaris-app-ServiceUrl'].Value" \
  --output text --region $REGION)

curl $SERVICE_URL/health
curl $SERVICE_URL/.well-known/jwks.json
```

---

## Updating Individual Stacks

| What changed | Re-deploy |
|---|---|
| VPC, subnets, NAT gateways | `01-core` |
| Security groups, WAF rules | `02-network-security` |
| DynamoDB config, TTL, backups | `03-data` |
| KMS keys, IAM policies, ECR, ECS cluster | `04-compute` |
| CodeBuild spec, pipeline stages | `05-pipeline` |
| ECS task definition, ALB, container env vars | `06-application` |
| OPA/Rego policies | `07-policy` |

---

## Tear Down

Tear down in reverse order. Empty S3 buckets first.

```bash
# Empty S3 buckets (CloudFormation cannot delete non-empty buckets)
aws s3 rm s3://abaris-pipeline-artifacts-$(aws sts get-caller-identity --query Account --output text) --recursive
aws s3 rm s3://abaris-opa-bundle-$(aws sts get-caller-identity --query Account --output text) --recursive

# Delete stacks in reverse order
for stack in abaris-policy abaris-application abaris-pipeline \
             abaris-compute abaris-data \
             abaris-network-security abaris-core; do
  aws cloudformation delete-stack --stack-name $stack --region $REGION
  aws cloudformation wait stack-delete-complete --stack-name $stack --region $REGION
  echo "$stack deleted"
done
```

> KMS keys enter a 7-day pending deletion window and cannot be immediately removed.
> DynamoDB tables are deleted immediately — back up the token registry if needed.
