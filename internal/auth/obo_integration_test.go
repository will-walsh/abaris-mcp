//go:build integration

// Package auth_test contains integration tests for OBO token store components.
//
// These tests require LocalStack running at http://localhost:4566 with KMS and DynamoDB enabled.
// Run with: go test -tags integration ./internal/auth/...
//
// Test cases:
//  1. DynamoDBTokenStore round-trip against LocalStack DynamoDB
//  2. EncryptedTokenStore round-trip against LocalStack KMS
//
// Validates: Requirements 11.3, 11.6, 15.2
package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/will-walsh/abaris-mcp/internal/auth"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

const localstackEndpointOBO = "http://localhost:4566"

func newLocalStackConfig(t *testing.T) aws.Config {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
		config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{
					URL:               localstackEndpointOBO,
					HostnameImmutable: true,
				}, nil
			}),
		),
	)
	if err != nil {
		t.Fatalf("load AWS config for LocalStack: %v", err)
	}
	return cfg
}

// createDynamoDBTable creates a test DynamoDB table in LocalStack.
func createDynamoDBTable(t *testing.T, client *dynamodb.Client, tableName string) {
	t.Helper()
	_, err := client.CreateTable(context.Background(), &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("user_id"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("provider"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("user_id"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("provider"), KeyType: types.KeyTypeRange},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		t.Fatalf("CreateTable %s: %v", tableName, err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{
			TableName: aws.String(tableName),
		})
	})
}

// createKMSSymmetricKey creates a symmetric KMS key in LocalStack for encryption.
func createKMSSymmetricKey(t *testing.T, client *kms.Client) string {
	t.Helper()
	out, err := client.CreateKey(context.Background(), &kms.CreateKeyInput{
		KeySpec:     kmstypes.KeySpecSymmetricDefault,
		KeyUsage:    kmstypes.KeyUsageTypeEncryptDecrypt,
		Description: aws.String("abaris-obo-integration-test-key"),
	})
	if err != nil {
		t.Fatalf("CreateKey (symmetric) in LocalStack: %v", err)
	}
	return aws.ToString(out.KeyMetadata.KeyId)
}

// ---------------------------------------------------------------------------
// Test 1: DynamoDBTokenStore round-trip against LocalStack
// Validates: Requirements 11.6, 15.2
// ---------------------------------------------------------------------------

func TestDynamoDBTokenStore_Integration_RoundTrip(t *testing.T) {
	cfg := newLocalStackConfig(t)
	dynamoClient := dynamodb.NewFromConfig(cfg)
	tableName := "abaris-obo-test-" + t.Name()
	createDynamoDBTable(t, dynamoClient, tableName)

	store := auth.NewDynamoDBTokenStore(dynamoClient, tableName, &noopLogger{})

	original := domain.TokenPair{
		AccessToken:  "integration-access-token",
		RefreshToken: "integration-refresh-token",
	}

	// Save.
	if err := store.Save(context.Background(), "user-integration-001", "github", original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Get — must return the same pair.
	retrieved, err := store.Get(context.Background(), "user-integration-001", "github")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if retrieved.AccessToken != original.AccessToken || retrieved.RefreshToken != original.RefreshToken {
		t.Errorf("round-trip mismatch: got %+v, want %+v", retrieved, original)
	}

	// Delete.
	if err := store.Delete(context.Background(), "user-integration-001", "github"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Get after delete — must return ErrNotConnected.
	_, err = store.Get(context.Background(), "user-integration-001", "github")
	if !errors.Is(err, domain.ErrNotConnected) {
		t.Errorf("expected ErrNotConnected after delete, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 2: EncryptedTokenStore round-trip against LocalStack KMS
// Validates: Requirements 11.3
// ---------------------------------------------------------------------------

func TestEncryptedTokenStore_Integration_RoundTrip(t *testing.T) {
	cfg := newLocalStackConfig(t)
	kmsClient := kms.NewFromConfig(cfg)
	keyID := createKMSSymmetricKey(t, kmsClient)

	// Use an in-memory backend for the encrypted store (KMS is the focus here).
	backend := newInMemoryBackend()
	store := auth.NewEncryptedTokenStore(backend, kmsClient, keyID, &noopLogger{})

	original := domain.TokenPair{
		AccessToken:  "encrypted-access-token-integration",
		RefreshToken: "encrypted-refresh-token-integration",
	}

	// Save (encrypts with KMS GenerateDataKey).
	if err := store.Save(context.Background(), "user-enc-001", "github", original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify the backend stores ciphertext, not plaintext.
	rawPair, err := backend.Get(context.Background(), "user-enc-001", "github")
	if err != nil {
		t.Fatalf("backend.Get: %v", err)
	}
	if rawPair.AccessToken == original.AccessToken {
		t.Error("backend should store ciphertext, not plaintext access token")
	}

	// Get (decrypts with KMS Decrypt).
	retrieved, err := store.Get(context.Background(), "user-enc-001", "github")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if retrieved.AccessToken != original.AccessToken || retrieved.RefreshToken != original.RefreshToken {
		t.Errorf("round-trip mismatch: got %+v, want %+v", retrieved, original)
	}
}
