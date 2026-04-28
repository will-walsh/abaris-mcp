package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// DynamoDBClient is the interface for DynamoDB operations used by DynamoDBTokenStore.
type DynamoDBClient interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// DynamoDBTokenStore implements domain.TokenStore using AWS DynamoDB.
// Partition key: "PK" (string), Sort key: "SK" (string).
// The token pair is stored as a JSON string in the "token_pair" attribute.
type DynamoDBTokenStore struct {
	client    DynamoDBClient
	tableName string
	logger    domain.Logger
}

// compile-time interface check
var _ domain.TokenStore = (*DynamoDBTokenStore)(nil)

// NewDynamoDBTokenStore creates a DynamoDBTokenStore.
func NewDynamoDBTokenStore(client DynamoDBClient, tableName string, logger domain.Logger) *DynamoDBTokenStore {
	return &DynamoDBTokenStore{client: client, tableName: tableName, logger: logger}
}

// Get retrieves the TokenPair for the given user and provider.
// Returns domain.ErrNotConnected if no item exists.
func (s *DynamoDBTokenStore) Get(ctx context.Context, userID, provider string) (domain.TokenPair, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: userID},
			"SK": &types.AttributeValueMemberS{Value: provider},
		},
	})
	if err != nil {
		return domain.TokenPair{}, fmt.Errorf("%w: dynamodb GetItem: %s", domain.ErrServiceUnavailable, err)
	}
	if out.Item == nil {
		return domain.TokenPair{}, fmt.Errorf("%w: user=%s provider=%s", domain.ErrNotConnected, userID, provider)
	}

	attr, ok := out.Item["token_pair"]
	if !ok {
		return domain.TokenPair{}, fmt.Errorf("%w: missing token_pair attribute", domain.ErrNotConnected)
	}
	sv, ok := attr.(*types.AttributeValueMemberS)
	if !ok {
		return domain.TokenPair{}, fmt.Errorf("token_store: unexpected attribute type for token_pair")
	}

	var pair domain.TokenPair
	if err := json.Unmarshal([]byte(sv.Value), &pair); err != nil {
		return domain.TokenPair{}, fmt.Errorf("token_store: unmarshal token pair: %w", err)
	}
	return pair, nil
}

// Save persists the TokenPair for the given user and provider.
func (s *DynamoDBTokenStore) Save(ctx context.Context, userID, provider string, pair domain.TokenPair) error {
	pairJSON, err := json.Marshal(pair)
	if err != nil {
		return fmt.Errorf("token_store: marshal token pair: %w", err)
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item: map[string]types.AttributeValue{
			"PK":         &types.AttributeValueMemberS{Value: userID},
			"SK":         &types.AttributeValueMemberS{Value: provider},
			"token_pair": &types.AttributeValueMemberS{Value: string(pairJSON)},
		},
	})
	if err != nil {
		return fmt.Errorf("%w: dynamodb PutItem: %s", domain.ErrServiceUnavailable, err)
	}
	return nil
}

// Delete removes the TokenPair for the given user and provider.
func (s *DynamoDBTokenStore) Delete(ctx context.Context, userID, provider string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: userID},
			"SK": &types.AttributeValueMemberS{Value: provider},
		},
	})
	if err != nil {
		return fmt.Errorf("%w: dynamodb DeleteItem: %s", domain.ErrServiceUnavailable, err)
	}
	return nil
}
