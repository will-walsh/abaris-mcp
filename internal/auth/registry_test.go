package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/will-walsh/abaris-mcp/internal/auth"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// ---------------------------------------------------------------------------
// Mock KMS client
// ---------------------------------------------------------------------------

type mockKMSClient struct {
	generateDataKeyFn func(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	decryptFn         func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

func (m *mockKMSClient) GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	return m.generateDataKeyFn(ctx, params, optFns...)
}

func (m *mockKMSClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return m.decryptFn(ctx, params, optFns...)
}

// ---------------------------------------------------------------------------
// Mock DynamoDB client
// ---------------------------------------------------------------------------

type mockDynamoDBClient struct {
	getItemFn    func(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	putItemFn    func(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	deleteItemFn func(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

func (m *mockDynamoDBClient) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return m.getItemFn(ctx, params, optFns...)
}

func (m *mockDynamoDBClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	return m.putItemFn(ctx, params, optFns...)
}

func (m *mockDynamoDBClient) DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	return m.deleteItemFn(ctx, params, optFns...)
}

// ---------------------------------------------------------------------------
// EncryptedTokenStore tests
// ---------------------------------------------------------------------------

// inMemoryBackend is a simple in-memory TokenStore for use as the backend in EncryptedTokenStore tests.
type inMemoryBackend struct {
	data map[string]domain.TokenPair
}

func newInMemoryBackend() *inMemoryBackend {
	return &inMemoryBackend{data: make(map[string]domain.TokenPair)}
}

func (b *inMemoryBackend) Get(_ context.Context, userID, provider string) (domain.TokenPair, error) {
	pair, ok := b.data[userID+":"+provider]
	if !ok {
		return domain.TokenPair{}, fmt.Errorf("%w", domain.ErrNotConnected)
	}
	return pair, nil
}

func (b *inMemoryBackend) Save(_ context.Context, userID, provider string, pair domain.TokenPair) error {
	b.data[userID+":"+provider] = pair
	return nil
}

func (b *inMemoryBackend) Delete(_ context.Context, userID, provider string) error {
	delete(b.data, userID+":"+provider)
	return nil
}

func TestEncryptedTokenStore_GenerateDataKeyError(t *testing.T) {
	kmsErr := errors.New("kms unavailable")
	mockKMS := &mockKMSClient{
		generateDataKeyFn: func(_ context.Context, _ *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			return nil, kmsErr
		},
	}
	store := auth.NewEncryptedTokenStore(newInMemoryBackend(), mockKMS, "arn:test", &noopLogger{})
	err := store.Save(context.Background(), "user1", "github", domain.TokenPair{AccessToken: "tok"})
	if !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got %v", err)
	}
}

func TestEncryptedTokenStore_DecryptError(t *testing.T) {
	// Use a real 32-byte key for GenerateDataKey (mock returns it as plaintext).
	plainKey := make([]byte, 32)
	for i := range plainKey {
		plainKey[i] = byte(i)
	}
	encryptedKey := []byte("encrypted-key-blob")

	mockKMS := &mockKMSClient{
		generateDataKeyFn: func(_ context.Context, _ *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			return &kms.GenerateDataKeyOutput{
				Plaintext:      plainKey,
				CiphertextBlob: encryptedKey,
			}, nil
		},
		decryptFn: func(_ context.Context, _ *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			return nil, errors.New("kms decrypt failed")
		},
	}
	backend := newInMemoryBackend()
	store := auth.NewEncryptedTokenStore(backend, mockKMS, "arn:test", &noopLogger{})

	// Save succeeds.
	if err := store.Save(context.Background(), "user1", "github", domain.TokenPair{AccessToken: "tok"}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Get fails with ErrServiceUnavailable.
	_, err := store.Get(context.Background(), "user1", "github")
	if !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable on Decrypt error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// DynamoDBTokenStore key format tests
// ---------------------------------------------------------------------------

func TestDynamoDBTokenStore_KeyFormat(t *testing.T) {
	var capturedGetKey map[string]types.AttributeValue
	var capturedPutItem map[string]types.AttributeValue

	mockDynamo := &mockDynamoDBClient{
		getItemFn: func(_ context.Context, params *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			capturedGetKey = params.Key
			return &dynamodb.GetItemOutput{Item: nil}, nil // not found
		},
		putItemFn: func(_ context.Context, params *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
			capturedPutItem = params.Item
			return &dynamodb.PutItemOutput{}, nil
		},
		deleteItemFn: func(_ context.Context, _ *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
			return &dynamodb.DeleteItemOutput{}, nil
		},
	}

	store := auth.NewDynamoDBTokenStore(mockDynamo, "abaris-tokens", &noopLogger{})

	// Test Get key format.
	_, _ = store.Get(context.Background(), "user-123", "github")
	if capturedGetKey == nil {
		t.Fatal("Get was not called")
	}
	userIDAttr, ok := capturedGetKey["user_id"].(*types.AttributeValueMemberS)
	if !ok || userIDAttr.Value != "user-123" {
		t.Errorf("expected user_id=user-123, got %v", capturedGetKey["user_id"])
	}
	providerAttr, ok := capturedGetKey["provider"].(*types.AttributeValueMemberS)
	if !ok || providerAttr.Value != "github" {
		t.Errorf("expected provider=github, got %v", capturedGetKey["provider"])
	}

	// Test Save key format.
	_ = store.Save(context.Background(), "user-123", "github", domain.TokenPair{AccessToken: "tok"})
	if capturedPutItem == nil {
		t.Fatal("Save was not called")
	}
	if _, ok := capturedPutItem["user_id"]; !ok {
		t.Error("PutItem missing user_id key")
	}
	if _, ok := capturedPutItem["provider"]; !ok {
		t.Error("PutItem missing provider key")
	}
	if _, ok := capturedPutItem["token_pair"]; !ok {
		t.Error("PutItem missing token_pair attribute")
	}
}

func TestDynamoDBTokenStore_GetNotFound(t *testing.T) {
	mockDynamo := &mockDynamoDBClient{
		getItemFn: func(_ context.Context, _ *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: nil}, nil
		},
		putItemFn:    func(_ context.Context, _ *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) { return &dynamodb.PutItemOutput{}, nil },
		deleteItemFn: func(_ context.Context, _ *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) { return &dynamodb.DeleteItemOutput{}, nil },
	}
	store := auth.NewDynamoDBTokenStore(mockDynamo, "abaris-tokens", &noopLogger{})
	_, err := store.Get(context.Background(), "user1", "github")
	if !errors.Is(err, domain.ErrNotConnected) {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// BadgerTokenStore key format tests
// ---------------------------------------------------------------------------

func TestBadgerTokenStore_KeyFormat(t *testing.T) {
	dir := t.TempDir()
	store, err := auth.NewBadgerTokenStore(dir, &noopLogger{})
	if err != nil {
		t.Fatalf("NewBadgerTokenStore: %v", err)
	}
	defer store.Close()

	// Save and retrieve — verifies the composite key works correctly.
	original := domain.TokenPair{AccessToken: "access-tok", RefreshToken: "refresh-tok"}
	if err := store.Save(context.Background(), "user-abc", "github", original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	retrieved, err := store.Get(context.Background(), "user-abc", "github")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if retrieved.AccessToken != original.AccessToken || retrieved.RefreshToken != original.RefreshToken {
		t.Errorf("round-trip mismatch: got %+v, want %+v", retrieved, original)
	}

	// Different user should not find the token.
	_, err = store.Get(context.Background(), "other-user", "github")
	if !errors.Is(err, domain.ErrNotConnected) {
		t.Errorf("expected ErrNotConnected for different user, got %v", err)
	}

	// Different provider should not find the token.
	_, err = store.Get(context.Background(), "user-abc", "gitlab")
	if !errors.Is(err, domain.ErrNotConnected) {
		t.Errorf("expected ErrNotConnected for different provider, got %v", err)
	}
}

func TestBadgerTokenStore_DeleteIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	store, err := auth.NewBadgerTokenStore(dir, &noopLogger{})
	if err != nil {
		t.Fatalf("NewBadgerTokenStore: %v", err)
	}
	defer store.Close()

	// Delete on non-existent key should not error.
	if err := store.Delete(context.Background(), "user1", "github"); err != nil {
		t.Errorf("Delete on non-existent key should not error, got %v", err)
	}
}
