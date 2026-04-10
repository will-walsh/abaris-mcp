package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// BadgerTokenStore implements domain.TokenStore using BadgerDB.
// Composite key format: "{userID}:{provider}"
// Intended for development/local use; not suitable for multi-instance deployments.
type BadgerTokenStore struct {
	db     *badger.DB
	logger domain.Logger
}

// compile-time interface check
var _ domain.TokenStore = (*BadgerTokenStore)(nil)

// NewBadgerTokenStore opens (or creates) a BadgerDB at dataDir and returns a BadgerTokenStore.
func NewBadgerTokenStore(dataDir string, logger domain.Logger) (*BadgerTokenStore, error) {
	opts := badger.DefaultOptions(dataDir).WithLogger(nil) // suppress badger's own logging
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("badger: open %s: %w", dataDir, err)
	}
	return &BadgerTokenStore{db: db, logger: logger}, nil
}

// Close closes the underlying BadgerDB. Call this on shutdown.
func (s *BadgerTokenStore) Close() error {
	return s.db.Close()
}

// badgerKey returns the composite key for a user+provider pair.
func badgerKey(userID, provider string) []byte {
	return []byte(userID + ":" + provider)
}

// Get retrieves the TokenPair for the given user and provider.
// Returns domain.ErrNotConnected if no entry exists.
func (s *BadgerTokenStore) Get(_ context.Context, userID, provider string) (domain.TokenPair, error) {
	var pair domain.TokenPair
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(badgerKey(userID, provider))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return fmt.Errorf("%w: user=%s provider=%s", domain.ErrNotConnected, userID, provider)
			}
			return fmt.Errorf("%w: badger Get: %s", domain.ErrServiceUnavailable, err)
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &pair)
		})
	})
	if err != nil {
		return domain.TokenPair{}, err
	}
	return pair, nil
}

// Save persists the TokenPair for the given user and provider.
func (s *BadgerTokenStore) Save(_ context.Context, userID, provider string, pair domain.TokenPair) error {
	val, err := json.Marshal(pair)
	if err != nil {
		return fmt.Errorf("badger: marshal token pair: %w", err)
	}
	return s.db.Update(func(txn *badger.Txn) error {
		if err := txn.Set(badgerKey(userID, provider), val); err != nil {
			return fmt.Errorf("%w: badger Set: %s", domain.ErrServiceUnavailable, err)
		}
		return nil
	})
}

// Delete removes the TokenPair for the given user and provider.
// Returns nil if the key does not exist (idempotent).
func (s *BadgerTokenStore) Delete(_ context.Context, userID, provider string) error {
	return s.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(badgerKey(userID, provider))
		if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return fmt.Errorf("%w: badger Delete: %s", domain.ErrServiceUnavailable, err)
		}
		return nil
	})
}
