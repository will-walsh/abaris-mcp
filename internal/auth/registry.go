package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// KMSClient is the interface for KMS operations used by EncryptedTokenStore.
// Defined here for testability — the production implementation uses the real AWS KMS client.
type KMSClient interface {
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// encryptedBlob is the structure stored in the backend for each token pair.
// All fields are base64-encoded bytes stored as JSON.
type encryptedBlob struct {
	EncryptedDataKey []byte `json:"edk"` // KMS-encrypted data key
	Ciphertext       []byte `json:"ct"`  // AES-256-GCM ciphertext
	Nonce            []byte `json:"n"`   // AES-256-GCM nonce (12 bytes)
}

// EncryptedTokenStore wraps a TokenStore backend with KMS envelope encryption.
// On Save: GenerateDataKey → AES-256-GCM encrypt → store blob.
// On Get: load blob → Decrypt data key → AES-256-GCM decrypt.
type EncryptedTokenStore struct {
	backend   domain.TokenStore
	kmsClient KMSClient
	kmsKeyARN string
	logger    domain.Logger
}

// compile-time interface check
var _ domain.TokenStore = (*EncryptedTokenStore)(nil)

// NewEncryptedTokenStore creates an EncryptedTokenStore wrapping the given backend.
func NewEncryptedTokenStore(backend domain.TokenStore, kmsClient KMSClient, kmsKeyARN string, logger domain.Logger) *EncryptedTokenStore {
	return &EncryptedTokenStore{
		backend:   backend,
		kmsClient: kmsClient,
		kmsKeyARN: kmsKeyARN,
		logger:    logger,
	}
}

// Save encrypts the TokenPair using KMS envelope encryption and stores it in the backend.
func (s *EncryptedTokenStore) Save(ctx context.Context, userID, provider string, pair domain.TokenPair) error {
	// 1. Generate a data key via KMS.
	dkOut, err := s.kmsClient.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(s.kmsKeyARN),
		KeySpec: kmstypes.DataKeySpecAes256,
	})
	if err != nil {
		s.logger.Error("token_store: GenerateDataKey failed", "user_id", userID, "provider", provider)
		return fmt.Errorf("%w: kms GenerateDataKey: %s", domain.ErrServiceUnavailable, err)
	}

	// 2. AES-256-GCM encrypt the TokenPair JSON.
	plaintext, err := json.Marshal(pair)
	if err != nil {
		return fmt.Errorf("token_store: marshal token pair: %w", err)
	}

	block, err := aes.NewCipher(dkOut.Plaintext)
	if err != nil {
		return fmt.Errorf("token_store: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("token_store: create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("token_store: generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// 3. Encode as blob and store in backend.
	blob := encryptedBlob{
		EncryptedDataKey: dkOut.CiphertextBlob,
		Ciphertext:       ciphertext,
		Nonce:            nonce,
	}
	blobBytes, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("token_store: marshal blob: %w", err)
	}

	// Store as a synthetic TokenPair where AccessToken holds the blob JSON.
	// The backend stores opaque bytes; encryption is transparent to it.
	syntheticPair := domain.TokenPair{AccessToken: string(blobBytes)}
	if err := s.backend.Save(ctx, userID, provider, syntheticPair); err != nil {
		return fmt.Errorf("token_store: backend save: %w", err)
	}

	s.logger.Info("token_store: saved encrypted token pair", "user_id", userID, "provider", provider)
	return nil
}

// Get retrieves and decrypts the TokenPair for the given user and provider.
func (s *EncryptedTokenStore) Get(ctx context.Context, userID, provider string) (domain.TokenPair, error) {
	syntheticPair, err := s.backend.Get(ctx, userID, provider)
	if err != nil {
		return domain.TokenPair{}, err // propagates ErrNotConnected from backend
	}

	// Decode the blob.
	var blob encryptedBlob
	if err := json.Unmarshal([]byte(syntheticPair.AccessToken), &blob); err != nil {
		return domain.TokenPair{}, fmt.Errorf("token_store: unmarshal blob: %w", err)
	}

	// Decrypt the data key via KMS.
	dkOut, err := s.kmsClient.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(s.kmsKeyARN),
		CiphertextBlob: blob.EncryptedDataKey,
	})
	if err != nil {
		s.logger.Error("token_store: Decrypt failed", "user_id", userID, "provider", provider)
		return domain.TokenPair{}, fmt.Errorf("%w: kms Decrypt: %s", domain.ErrServiceUnavailable, err)
	}

	// AES-256-GCM decrypt.
	block, err := aes.NewCipher(dkOut.Plaintext)
	if err != nil {
		return domain.TokenPair{}, fmt.Errorf("token_store: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return domain.TokenPair{}, fmt.Errorf("token_store: create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, blob.Nonce, blob.Ciphertext, nil)
	if err != nil {
		return domain.TokenPair{}, fmt.Errorf("token_store: decrypt: %w", err)
	}

	var pair domain.TokenPair
	if err := json.Unmarshal(plaintext, &pair); err != nil {
		return domain.TokenPair{}, fmt.Errorf("token_store: unmarshal token pair: %w", err)
	}

	s.logger.Info("token_store: retrieved encrypted token pair", "user_id", userID, "provider", provider)
	return pair, nil
}

// Delete removes the TokenPair for the given user and provider.
func (s *EncryptedTokenStore) Delete(ctx context.Context, userID, provider string) error {
	if err := s.backend.Delete(ctx, userID, provider); err != nil {
		return fmt.Errorf("token_store: backend delete: %w", err)
	}
	s.logger.Info("token_store: deleted token pair", "user_id", userID, "provider", provider)
	return nil
}
