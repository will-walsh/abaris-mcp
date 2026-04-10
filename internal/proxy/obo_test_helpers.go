package proxy

import (
	"context"

	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// WithOBOContextForTest is a test helper that injects OBO context into ctx.
// Only for use in tests.
func WithOBOContextForTest(ctx context.Context, store domain.TokenStore, userID, provider string) context.Context {
	return withOBOContext(ctx, store, userID, provider)
}
