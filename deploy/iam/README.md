# Abaris App Runner IAM Role

## Files

- `abaris-apprunner-trust-policy.json` — trust policy allowing App Runner task principal to assume the role
- `abaris-apprunner-policy.json` — least-privilege permissions policy for the Abaris service role

## Permissions Summary

| Statement | Actions | Resource scope |
|---|---|---|
| `KMSSigningKeyPermissions` | `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` | Signing key only |
| `KMSEncryptionKeyPermissions` | `kms:GenerateDataKey`, `kms:Decrypt` | Encryption key only |
| `DynamoDBTokenTablePermissions` | `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem` | Token table only |
| `SecretsManagerPermissions` | `secretsmanager:GetSecretValue` | `abaris/*` secrets only |

## Resource Placeholders

Before deploying, substitute the following placeholders in `abaris-apprunner-policy.json`:

| Placeholder | Description |
|---|---|
| `${KMS_SIGNING_KEY_ID}` | KMS key ID or ARN for the RS256 signing key (`kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey`) |
| `${KMS_ENCRYPTION_KEY_ID}` | KMS key ID or ARN for the AES-256 envelope encryption key (`kms:GenerateDataKey`, `kms:Decrypt`) |
| `${DYNAMODB_TOKEN_TABLE_NAME}` | DynamoDB table name used by `EncryptedTokenStore` |

If the signing key and encryption key are the same KMS key, use the same key ID for both placeholders and merge the two KMS statements into one.

## Deployment (AWS CLI)

```bash
# 1. Create the IAM role with the App Runner trust policy
aws iam create-role \
  --role-name AbarisAppRunnerRole \
  --assume-role-policy-document file://abaris-apprunner-trust-policy.json

# 2. Create the permissions policy
aws iam create-policy \
  --policy-name AbarisAppRunnerPolicy \
  --policy-document file://abaris-apprunner-policy.json

# 3. Attach the policy to the role
aws iam attach-role-policy \
  --role-name AbarisAppRunnerRole \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/AbarisAppRunnerPolicy
```

## Notes

- The `secretsmanager:GetSecretValue` action is scoped to `abaris/*` — all Abaris secrets must be stored under this prefix (e.g. `abaris/service-credentials`, `abaris/github-client-secret`).
- The KMS statements use `kms:RequestAlias` conditions as an additional guard. Remove the `Condition` block if you reference keys by ARN directly in the `Resource` field.
- No `kms:Encrypt` permission is granted — `EncryptedTokenStore` uses `kms:GenerateDataKey` (envelope encryption) rather than direct KMS encryption, which is the correct pattern for encrypting arbitrary-length data.
