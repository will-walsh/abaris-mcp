# CloudWatch Log Group Configuration

App Runner automatically streams container stdout to CloudWatch Logs when the
service is configured with an instance role that has `logs:CreateLogGroup`,
`logs:CreateLogStream`, and `logs:PutLogEvents` permissions.

The resources below create the log group with a 90-day retention policy and
wire it to the App Runner service via an observability configuration.

## CloudFormation / SAM snippet

```yaml
# deploy/cloudwatch/apprunner-logs.yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: CloudWatch log group and App Runner observability config for Abaris

Parameters:
  AppName:
    Type: String
    Default: abaris
  RetentionDays:
    Type: Number
    Default: 90
    AllowedValues: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653]

Resources:
  AbarisLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/apprunner/${AppName}"
      RetentionInDays: !Ref RetentionDays
      Tags:
        - Key: app
          Value: !Ref AppName

  AbarisObservabilityConfig:
    Type: AWS::AppRunner::ObservabilityConfiguration
    Properties:
      ObservabilityConfigurationName: !Sub "${AppName}-observability"
      TraceConfiguration:
        Vendor: AWSXRAY
      Tags:
        - Key: app
          Value: !Ref AppName

  # Attach to your App Runner service by referencing this config ARN in
  # the AWS::AppRunner::Service ObservabilityConfiguration property.
  # App Runner writes stdout/stderr to:
  #   /aws/apprunner/<service-name>/<service-id>/application
  #   /aws/apprunner/<service-name>/<service-id>/system
```

## AWS CLI commands (imperative alternative)

```bash
# 1. Create the log group
aws logs create-log-group \
  --log-group-name "/aws/apprunner/abaris" \
  --region "${AWS_REGION}"

# 2. Set retention policy (90 days)
aws logs put-retention-policy \
  --log-group-name "/aws/apprunner/abaris" \
  --retention-in-days 90 \
  --region "${AWS_REGION}"

# 3. Tag the log group
aws logs tag-log-group \
  --log-group-name "/aws/apprunner/abaris" \
  --tags app=abaris \
  --region "${AWS_REGION}"
```

## IAM additions required on the App Runner instance role

Add the following statement to `deploy/iam/abaris-apprunner-policy.json` so
the App Runner service role can write logs:

```json
{
  "Sid": "CloudWatchLogsPermissions",
  "Effect": "Allow",
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
    "logs:DescribeLogStreams"
  ],
  "Resource": "arn:aws:logs:*:*:log-group:/aws/apprunner/abaris:*"
}
```

## Notes

- Abaris emits all log output to **stdout** in JSON format (Requirement 9.3).
  App Runner captures stdout and forwards it to CloudWatch automatically — no
  log agent or sidecar is required.
- The log group name `/aws/apprunner/abaris` is the App Runner default; it is
  created automatically by App Runner if the instance role has the permissions
  above. The CloudFormation resource above pre-creates it with an explicit
  retention policy so logs are not retained indefinitely.
- For structured log querying, use CloudWatch Logs Insights with JSON field
  extraction, e.g.:
  ```
  fields @timestamp, level, msg, caller_user_id, tool_name, decision_outcome
  | filter level = "INFO" and msg = "policy_decision"
  | sort @timestamp desc
  ```
