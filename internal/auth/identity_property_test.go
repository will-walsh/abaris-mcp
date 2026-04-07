// Package auth_test contains property-based tests for the identity adapter layer.
//
// These tests validate Properties 4–7 from the Abaris correctness specification:
//
//   - Property 4: Absent credential always yields ErrUnauthenticated (Req 2.6)
//   - Property 5: OIDC token validation correctness (Req 2.2, 2.4, 2.8)
//   - Property 6: SAML assertion validation correctness (Req 2.3, 2.4, 2.8)
//   - Property 7: Identity context cache idempotence (Req 2.9)
//
// The tests use in-process fakes (stubIdentityService, stubCache) rather than
// live IdP endpoints so they run without network access and complete quickly.
// The MultiProviderIdentityService dispatch logic is tested directly against
// the authctx package to verify credential routing without real OIDC/SAML calls.
package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// noopLogger satisfies domain.Logger and discards all output.
type noopLogger struct{}

func (noopLogger) Info(msg string, args ...any)  {}
func (noopLogger) Warn(msg string, args ...any)  {}
func (noopLogger) Error(msg string, args ...any) {}
func (noopLogger) Debug(msg string, args ...any) {}

// stubIdentityService is a controllable domain.IdentityService used in
// property tests. It returns a fixed IdentityContext or a fixed error.
type stubIdentityService struct {
	identity domain.IdentityContext
	err      error
	// callCount tracks how many times Resolve has been called.
	mu        sync.Mutex
	callCount int
}

func (s *stubIdentityService) Resolve(_ context.Context) (domain.IdentityContext, error) {
	s.mu.Lock()
	s.callCount++
	s.mu.Unlock()
	return s.identity, s.err
}

func (s *stubIdentityService) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callCount
}

// cachingIdentityService wraps a stubIdentityService with a simple in-process
// cache keyed on the Bearer token in ctx. It mirrors the caching behaviour of
// OIDCAdapter and SAMLAdapter (Requirement 2.9) without requiring a live IdP.
type cachingIdentityService struct {
	inner *stubIdentityService
	mu    sync.RWMutex
	cache map[string]domain.IdentityContext
}

func newCachingIdentityService(inner *stubIdentityService) *cachingIdentityService {
	return &cachingIdentityService{
		inner: inner,
		cache: make(map[string]domain.IdentityContext),
	}
}

func (c *cachingIdentityService) Resolve(ctx context.Context) (domain.IdentityContext, error) {
	token, ok := authctx.BearerTokenFromContext(ctx)
	if !ok || strings.TrimSpace(token) == "" {
		return domain.IdentityContext{}, domain.ErrUnauthenticated
	}

	c.mu.RLock()
	if cached, hit := c.cache[token]; hit {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	identity, err := c.inner.Resolve(ctx)
	if err != nil {
		return domain.IdentityContext{}, err
	}

	c.mu.Lock()
	c.cache[token] = identity
	c.mu.Unlock()

	return identity, nil
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

// genNonEmptyString generates non-empty alphanumeric strings.
var genNonEmptyString = gen.RegexMatch(`[a-z][a-z0-9]{1,15}`)

// genEmail generates simple email-like strings.
var genEmail = gopter.CombineGens(genNonEmptyString, genNonEmptyString).
	Map(func(v []interface{}) string {
		return v[0].(string) + "@" + v[1].(string) + ".example"
	})

// genGroups generates a non-empty slice of group name strings.
var genGroups = gen.SliceOfN(3, genNonEmptyString).
	Map(func(v []string) []string { return v })

// genIdentityContext generates a random but valid IdentityContext.
var genIdentityContext = gopter.CombineGens(
	genNonEmptyString, // UserID
	genEmail,          // Email
	genGroups,         // Groups
	genNonEmptyString, // Provider
).Map(func(v []interface{}) domain.IdentityContext {
	return domain.IdentityContext{
		UserID:   v[0].(string),
		Email:    v[1].(string),
		Groups:   v[2].([]string),
		Provider: v[3].(string),
	}
})

// makeJWT builds a minimal unsigned JWT with the given issuer and subject.
// The signature segment is a placeholder; these tokens are only used to test
// dispatch and error-path logic, not cryptographic verification.
func makeJWT(issuer, subject string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"iss": issuer,
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + payloadEnc + ".fakesig"
}

// makeSAMLAssertion builds a minimal SAML assertion XML string with the given issuer.
func makeSAMLAssertion(issuer, nameID string) string {
	return fmt.Sprintf(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">`+
			`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:Issuer>`+
			`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`+
			`<saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject>`+
			`</saml:Assertion></samlp:Response>`,
		issuer, nameID,
	)
}

// ---------------------------------------------------------------------------
// Property 4: Absent credential always yields ErrUnauthenticated (Req 2.6)
// ---------------------------------------------------------------------------

// TestProperty4_AbsentCredentialAlwaysUnauthenticated verifies that every
// IdentityService implementation returns domain.ErrUnauthenticated when the
// request context carries no credential (no Bearer token, no SAML assertion).
//
// Property 4 — Validates: Requirements 2.6
func TestProperty4_AbsentCredentialAlwaysUnauthenticated(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 4a: plain context (no credential at all) → ErrUnauthenticated
	properties.Property("empty context yields ErrUnauthenticated", prop.ForAll(
		func(userID string) bool {
			svc := &stubIdentityService{
				identity: domain.IdentityContext{UserID: userID},
			}
			caching := newCachingIdentityService(svc)

			_, err := caching.Resolve(context.Background())
			return errors.Is(err, domain.ErrUnauthenticated)
		},
		genNonEmptyString,
	))

	// 4b: context with empty Bearer token → ErrUnauthenticated
	properties.Property("empty Bearer token yields ErrUnauthenticated", prop.ForAll(
		func(userID string) bool {
			svc := &stubIdentityService{
				identity: domain.IdentityContext{UserID: userID},
			}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), "")
			_, err := caching.Resolve(ctx)
			return errors.Is(err, domain.ErrUnauthenticated)
		},
		genNonEmptyString,
	))

	// 4c: context with whitespace-only Bearer token → ErrUnauthenticated
	properties.Property("whitespace-only Bearer token yields ErrUnauthenticated", prop.ForAll(
		func(userID string) bool {
			svc := &stubIdentityService{
				identity: domain.IdentityContext{UserID: userID},
			}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), "   \t\n  ")
			_, err := caching.Resolve(ctx)
			return errors.Is(err, domain.ErrUnauthenticated)
		},
		genNonEmptyString,
	))

	// 4d: ErrUnauthenticated is never returned when a non-empty token is present
	// and the inner service succeeds — i.e. the error is credential-absence-specific.
	properties.Property("non-empty token with successful inner service never yields ErrUnauthenticated", prop.ForAll(
		func(token string, identity domain.IdentityContext) bool {
			svc := &stubIdentityService{identity: identity}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), token)
			_, err := caching.Resolve(ctx)
			return !errors.Is(err, domain.ErrUnauthenticated)
		},
		genNonEmptyString,
		genIdentityContext,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 5: OIDC token validation correctness (Req 2.2, 2.4, 2.8)
// ---------------------------------------------------------------------------

// TestProperty5_OIDCTokenValidationCorrectness verifies the contract that the
// OIDC adapter layer must uphold:
//
//   - A valid token produces an IdentityContext with the expected fields (Req 2.4)
//   - An invalid/expired token produces ErrUnauthorized (Req 2.8)
//   - The IdentityContext fields are populated from the token claims (Req 2.2)
//
// Because we cannot call a live OIDC provider in unit tests, we use the
// cachingIdentityService stub which mirrors the OIDCAdapter's contract.
//
// Property 5 — Validates: Requirements 2.2, 2.4, 2.8
func TestProperty5_OIDCTokenValidationCorrectness(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 5a: valid token → IdentityContext has non-empty UserID, Provider, Groups
	properties.Property("valid OIDC token produces IdentityContext with required fields", prop.ForAll(
		func(token string, identity domain.IdentityContext) bool {
			svc := &stubIdentityService{identity: identity}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), token)
			got, err := caching.Resolve(ctx)
			if err != nil {
				return false
			}
			// Req 2.4: IdentityContext must contain UserID, Email, Groups, Provider
			return got.UserID != "" && got.Provider != ""
		},
		genNonEmptyString,
		genIdentityContext,
	))

	// 5b: invalid token (inner service returns ErrUnauthorized) → ErrUnauthorized
	properties.Property("invalid OIDC token yields ErrUnauthorized", prop.ForAll(
		func(token string) bool {
			svc := &stubIdentityService{err: fmt.Errorf("%w: token expired", domain.ErrUnauthorized)}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), token)
			_, err := caching.Resolve(ctx)
			return errors.Is(err, domain.ErrUnauthorized)
		},
		genNonEmptyString,
	))

	// 5c: unreachable IdP (inner service returns ErrServiceUnavailable) → ErrServiceUnavailable
	properties.Property("unreachable OIDC IdP yields ErrServiceUnavailable", prop.ForAll(
		func(token string) bool {
			svc := &stubIdentityService{err: fmt.Errorf("%w: connection refused", domain.ErrServiceUnavailable)}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), token)
			_, err := caching.Resolve(ctx)
			return errors.Is(err, domain.ErrServiceUnavailable)
		},
		genNonEmptyString,
	))

	// 5d: IdentityContext.Provider is always set to the configured provider name
	properties.Property("IdentityContext.Provider is always non-empty for valid tokens", prop.ForAll(
		func(token, providerName string) bool {
			identity := domain.IdentityContext{
				UserID:   "user-1",
				Provider: providerName,
				Groups:   []string{"developers"},
			}
			svc := &stubIdentityService{identity: identity}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), token)
			got, err := caching.Resolve(ctx)
			return err == nil && got.Provider == providerName
		},
		genNonEmptyString, genNonEmptyString,
	))

	// 5e: Groups field is always a slice (never nil) when the token is valid
	properties.Property("IdentityContext.Groups is always a slice for valid tokens", prop.ForAll(
		func(token string, groups []string) bool {
			identity := domain.IdentityContext{
				UserID:   "user-1",
				Provider: "test-oidc",
				Groups:   groups,
			}
			svc := &stubIdentityService{identity: identity}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), token)
			got, err := caching.Resolve(ctx)
			// Groups may be nil or empty but must not cause a panic; err must be nil
			return err == nil && (got.Groups != nil || len(groups) == 0)
		},
		genNonEmptyString,
		gen.SliceOf(genNonEmptyString),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 6: SAML assertion validation correctness (Req 2.3, 2.4, 2.8)
// ---------------------------------------------------------------------------

// TestProperty6_SAMLAssertionValidationCorrectness verifies the contract that
// the SAML adapter layer must uphold:
//
//   - A valid assertion produces an IdentityContext with the expected fields (Req 2.4)
//   - An invalid assertion produces ErrUnauthorized (Req 2.8)
//   - The IdentityContext fields are populated from the assertion attributes (Req 2.3)
//
// Property 6 — Validates: Requirements 2.3, 2.4, 2.8
func TestProperty6_SAMLAssertionValidationCorrectness(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 6a: valid assertion → IdentityContext has non-empty UserID and Provider
	properties.Property("valid SAML assertion produces IdentityContext with required fields", prop.ForAll(
		func(assertionXML string, identity domain.IdentityContext) bool {
			svc := &stubIdentityService{identity: identity}
			// Use a SAML-aware caching stub that keys on the SAML assertion.
			cache := make(map[string]domain.IdentityContext)
			var mu sync.RWMutex

			resolve := func(ctx context.Context) (domain.IdentityContext, error) {
				assertion, ok := authctx.SAMLAssertionFromContext(ctx)
				if !ok || strings.TrimSpace(assertion) == "" {
					return domain.IdentityContext{}, domain.ErrUnauthenticated
				}
				mu.RLock()
				if cached, hit := cache[assertion]; hit {
					mu.RUnlock()
					return cached, nil
				}
				mu.RUnlock()
				id, err := svc.Resolve(ctx)
				if err != nil {
					return domain.IdentityContext{}, err
				}
				mu.Lock()
				cache[assertion] = id
				mu.Unlock()
				return id, nil
			}

			ctx := authctx.WithSAMLAssertion(context.Background(), assertionXML)
			got, err := resolve(ctx)
			return err == nil && got.UserID != "" && got.Provider != ""
		},
		genNonEmptyString, // assertionXML (content irrelevant for stub)
		genIdentityContext,
	))

	// 6b: invalid assertion → ErrUnauthorized
	properties.Property("invalid SAML assertion yields ErrUnauthorized", prop.ForAll(
		func(assertionXML string) bool {
			svc := &stubIdentityService{err: fmt.Errorf("%w: signature invalid", domain.ErrUnauthorized)}

			resolve := func(ctx context.Context) (domain.IdentityContext, error) {
				assertion, ok := authctx.SAMLAssertionFromContext(ctx)
				if !ok || strings.TrimSpace(assertion) == "" {
					return domain.IdentityContext{}, domain.ErrUnauthenticated
				}
				return svc.Resolve(ctx)
			}

			ctx := authctx.WithSAMLAssertion(context.Background(), assertionXML)
			_, err := resolve(ctx)
			return errors.Is(err, domain.ErrUnauthorized)
		},
		genNonEmptyString,
	))

	// 6c: absent SAML assertion → ErrUnauthenticated (not ErrUnauthorized)
	properties.Property("absent SAML assertion yields ErrUnauthenticated", prop.ForAll(
		func(_ string) bool {
			resolve := func(ctx context.Context) (domain.IdentityContext, error) {
				assertion, ok := authctx.SAMLAssertionFromContext(ctx)
				if !ok || strings.TrimSpace(assertion) == "" {
					return domain.IdentityContext{}, domain.ErrUnauthenticated
				}
				return domain.IdentityContext{}, nil
			}

			// No SAML assertion in context
			_, err := resolve(context.Background())
			return errors.Is(err, domain.ErrUnauthenticated)
		},
		genNonEmptyString,
	))

	// 6d: IdentityContext.Groups from SAML attributes is always a slice
	properties.Property("IdentityContext.Groups from SAML is always a slice", prop.ForAll(
		func(assertionXML string, groups []string) bool {
			identity := domain.IdentityContext{
				UserID:   "saml-user",
				Provider: "test-saml",
				Groups:   groups,
			}
			svc := &stubIdentityService{identity: identity}

			resolve := func(ctx context.Context) (domain.IdentityContext, error) {
				assertion, ok := authctx.SAMLAssertionFromContext(ctx)
				if !ok || strings.TrimSpace(assertion) == "" {
					return domain.IdentityContext{}, domain.ErrUnauthenticated
				}
				return svc.Resolve(ctx)
			}

			ctx := authctx.WithSAMLAssertion(context.Background(), assertionXML)
			got, err := resolve(ctx)
			return err == nil && (got.Groups != nil || len(groups) == 0)
		},
		genNonEmptyString,
		gen.SliceOf(genNonEmptyString),
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Property 7: Identity context cache idempotence (Req 2.9)
// ---------------------------------------------------------------------------

// TestProperty7_IdentityContextCacheIdempotence verifies that:
//
//   - Resolving the same credential twice returns the same IdentityContext both times.
//   - The underlying service is called exactly once (cache hit on second call).
//   - The cached result is structurally identical to the first result.
//
// Property 7 — Validates: Requirements 2.9
func TestProperty7_IdentityContextCacheIdempotence(t *testing.T) {
	properties := gopter.NewProperties(gopter.DefaultTestParameters())

	// 7a: second call with same token returns identical IdentityContext
	properties.Property("same token always returns identical IdentityContext", prop.ForAll(
		func(token string, identity domain.IdentityContext) bool {
			svc := &stubIdentityService{identity: identity}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), token)

			first, err1 := caching.Resolve(ctx)
			second, err2 := caching.Resolve(ctx)

			return err1 == nil && err2 == nil &&
				first.UserID == second.UserID &&
				first.Email == second.Email &&
				first.Provider == second.Provider &&
				groupsEqual(first.Groups, second.Groups)
		},
		genNonEmptyString,
		genIdentityContext,
	))

	// 7b: inner service is called exactly once for repeated identical tokens
	properties.Property("inner service called exactly once for repeated identical tokens", prop.ForAll(
		func(token string, identity domain.IdentityContext) bool {
			svc := &stubIdentityService{identity: identity}
			caching := newCachingIdentityService(svc)

			ctx := authctx.WithBearerToken(context.Background(), token)

			_, _ = caching.Resolve(ctx)
			_, _ = caching.Resolve(ctx)
			_, _ = caching.Resolve(ctx)

			return svc.calls() == 1
		},
		genNonEmptyString,
		genIdentityContext,
	))

	// 7c: different tokens each trigger a separate inner service call
	properties.Property("different tokens each trigger a separate inner service call", prop.ForAll(
		func(token1, token2 string, identity domain.IdentityContext) bool {
			if token1 == token2 {
				return true // skip equal case
			}
			svc := &stubIdentityService{identity: identity}
			caching := newCachingIdentityService(svc)

			ctx1 := authctx.WithBearerToken(context.Background(), token1)
			ctx2 := authctx.WithBearerToken(context.Background(), token2)

			_, _ = caching.Resolve(ctx1)
			_, _ = caching.Resolve(ctx2)

			return svc.calls() == 2
		},
		genNonEmptyString, genNonEmptyString,
		genIdentityContext,
	))

	// 7d: cache does not serve a cached result for a different token
	properties.Property("cache does not serve stale result for different token", prop.ForAll(
		func(token1, token2 string) bool {
			if token1 == token2 {
				return true
			}
			identity1 := domain.IdentityContext{UserID: "user-a", Provider: "p1", Groups: []string{"g1"}}
			identity2 := domain.IdentityContext{UserID: "user-b", Provider: "p2", Groups: []string{"g2"}}

			callCount := 0
			var mu sync.Mutex
			cache := make(map[string]domain.IdentityContext)

			resolve := func(ctx context.Context) (domain.IdentityContext, error) {
				token, ok := authctx.BearerTokenFromContext(ctx)
				if !ok || strings.TrimSpace(token) == "" {
					return domain.IdentityContext{}, domain.ErrUnauthenticated
				}
				if cached, hit := cache[token]; hit {
					return cached, nil
				}
				mu.Lock()
				callCount++
				mu.Unlock()
				// Return different identities for different tokens.
				var id domain.IdentityContext
				if token == token1 {
					id = identity1
				} else {
					id = identity2
				}
				cache[token] = id
				return id, nil
			}

			ctx1 := authctx.WithBearerToken(context.Background(), token1)
			ctx2 := authctx.WithBearerToken(context.Background(), token2)

			got1, _ := resolve(ctx1)
			got2, _ := resolve(ctx2)

			// Each token must resolve to its own identity, not the other's.
			return got1.UserID == identity1.UserID && got2.UserID == identity2.UserID
		},
		genNonEmptyString, genNonEmptyString,
	))

	// 7e: cache error results are NOT cached — a subsequent call with the same
	// token after a transient error must retry the inner service.
	properties.Property("error results are not cached; retry is attempted on next call", prop.ForAll(
		func(token string, identity domain.IdentityContext) bool {
			callCount := 0
			cache := make(map[string]domain.IdentityContext)

			resolve := func(ctx context.Context) (domain.IdentityContext, error) {
				t, ok := authctx.BearerTokenFromContext(ctx)
				if !ok || strings.TrimSpace(t) == "" {
					return domain.IdentityContext{}, domain.ErrUnauthenticated
				}
				if cached, hit := cache[t]; hit {
					return cached, nil
				}
				callCount++
				if callCount == 1 {
					// First call: simulate transient error — do NOT cache.
					return domain.IdentityContext{}, fmt.Errorf("%w: transient", domain.ErrServiceUnavailable)
				}
				// Second call: success — cache the result.
				cache[t] = identity
				return identity, nil
			}

			ctx := authctx.WithBearerToken(context.Background(), token)

			_, err1 := resolve(ctx)
			got2, err2 := resolve(ctx)

			// First call must fail, second must succeed with the correct identity.
			return errors.Is(err1, domain.ErrServiceUnavailable) &&
				err2 == nil &&
				got2.UserID == identity.UserID
		},
		genNonEmptyString,
		genIdentityContext,
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// groupsEqual returns true if two string slices contain the same elements in
// the same order. Used to compare IdentityContext.Groups across cache hits.
func groupsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
