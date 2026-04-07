// Package infra contains infrastructure adapters that implement domain
// interfaces. Nothing in internal/domain imports this package.
package infra

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// SecretsClient is the minimal AWS Secrets Manager interface required by
// SecretsManagerAdapter. The production implementation is *secretsmanager.Client;
// tests can inject a mock.
type SecretsClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// compile-time check: the real AWS SDK client satisfies SecretsClient.
var _ SecretsClient = (*secretsmanager.Client)(nil)

// SecretsManagerAdapter retrieves secrets from AWS Secrets Manager using the
// ambient IAM role credentials. Region and secret ARNs are accepted exclusively
// from environment variables — no default values are applied.
type SecretsManagerAdapter struct {
	client SecretsClient
	logger domain.Logger
}

// NewSecretsManagerAdapter creates a SecretsManagerAdapter using the ambient
// IAM role credentials. region must be a non-empty AWS region string (e.g.
// "us-east-1"). No static credentials are accepted; the adapter relies entirely
// on the ambient IAM role attached to the execution environment.
func NewSecretsManagerAdapter(ctx context.Context, region string, logger domain.Logger) (*SecretsManagerAdapter, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("%w: loading AWS config: %s", domain.ErrServiceUnavailable, err)
	}
	client := secretsmanager.NewFromConfig(cfg)
	return &SecretsManagerAdapter{client: client, logger: logger}, nil
}

// NewSecretsManagerAdapterWithClient creates a SecretsManagerAdapter with an
// injected SecretsClient. Intended for use in tests.
func NewSecretsManagerAdapterWithClient(client SecretsClient, logger domain.Logger) *SecretsManagerAdapter {
	return &SecretsManagerAdapter{client: client, logger: logger}
}

// GetServiceCredentials retrieves the Service_Credentials secret identified by
// secretARN from AWS Secrets Manager and returns the raw secret string.
//
// Returns:
//   - domain.ErrServiceUnavailable (wrapped) if Secrets Manager is unreachable or
//     the request fails for any reason other than a missing secret.
//   - domain.ErrUnauthorized (wrapped) if the secret ARN does not exist
//     (ResourceNotFoundException).
func (a *SecretsManagerAdapter) GetServiceCredentials(ctx context.Context, secretARN string) (string, error) {
	return a.getSecret(ctx, secretARN, "service credentials")
}

// GetIDPClientSecret retrieves an Identity Provider client secret identified by
// secretARN from AWS Secrets Manager and returns the raw secret string.
//
// Returns:
//   - domain.ErrServiceUnavailable (wrapped) if Secrets Manager is unreachable or
//     the request fails for any reason other than a missing secret.
//   - domain.ErrUnauthorized (wrapped) if the secret ARN does not exist
//     (ResourceNotFoundException).
func (a *SecretsManagerAdapter) GetIDPClientSecret(ctx context.Context, secretARN string) (string, error) {
	return a.getSecret(ctx, secretARN, "IDP client secret")
}

// getSecret is the shared retrieval implementation. secretKind is a human-readable
// label used in log and error messages only.
func (a *SecretsManagerAdapter) getSecret(ctx context.Context, secretARN, secretKind string) (string, error) {
	out, err := a.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	})
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			a.logger.Error("secret not found in Secrets Manager",
				"secret_arn", secretARN,
				"kind", secretKind,
			)
			return "", fmt.Errorf("%w: %s not found at ARN %s", domain.ErrUnauthorized, secretKind, secretARN)
		}
		a.logger.Error("Secrets Manager unreachable",
			"secret_arn", secretARN,
			"kind", secretKind,
			"error", err,
		)
		return "", fmt.Errorf("%w: retrieving %s from Secrets Manager: %s", domain.ErrServiceUnavailable, secretKind, err)
	}

	if out.SecretString == nil {
		a.logger.Error("secret has no string value",
			"secret_arn", secretARN,
			"kind", secretKind,
		)
		return "", fmt.Errorf("%w: %s at ARN %s has no string value", domain.ErrServiceUnavailable, secretKind, secretARN)
	}

	return *out.SecretString, nil
}

// MustGetSecret retrieves the secret at secretARN from AWS Secrets Manager.
// It is intended for use at startup only. On any failure it logs at ERROR level
// (domain.Logger has no Fatal level) and calls os.Exit(1) so the process
// terminates with a non-zero exit code before serving any traffic.
//
//   - ResourceNotFoundException: logs a fatal-level message identifying the
//     missing ARN, then exits.
//   - Any other error (unreachable, auth failure, etc.): logs a fatal-level
//     message indicating Secrets Manager is unreachable, then exits.
//   - Success: returns the secret string value.
func MustGetSecret(ctx context.Context, adapter *SecretsManagerAdapter, secretARN string, logger domain.Logger) string {
	out, err := adapter.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	})
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			logger.Error("FATAL: secret not found in Secrets Manager — check the ARN and that the secret exists",
				"secret_arn", secretARN,
			)
			os.Exit(1)
		}
		logger.Error("FATAL: Secrets Manager is unreachable — check network connectivity and IAM permissions",
			"secret_arn", secretARN,
			"error", err,
		)
		os.Exit(1)
	}

	if out.SecretString == nil {
		logger.Error("FATAL: secret has no string value (binary secrets are not supported)",
			"secret_arn", secretARN,
		)
		os.Exit(1)
	}

	return *out.SecretString
}

// MustLoadSecrets iterates arns, calls MustGetSecret for each, and returns a
// map of ARN → secret string value. The process exits with a non-zero code on
// the first failure. This is the function the composition root calls at startup
// to eagerly validate all required secrets before serving any traffic.
func MustLoadSecrets(ctx context.Context, adapter *SecretsManagerAdapter, arns []string, logger domain.Logger) map[string]string {
	result := make(map[string]string, len(arns))
	for _, arn := range arns {
		result[arn] = MustGetSecret(ctx, adapter, arn, logger)
	}
	return result
}
