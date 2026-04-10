// Package saml provides a SAMLAdapter that implements domain.IdentityService
// by validating SAML 2.0 assertions using the crewjam/saml library and
// normalizing the resulting attributes into a domain.IdentityContext.
package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/jellydator/ttlcache/v3"
	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// SAMLAdapter implements domain.IdentityService for SAML 2.0 assertion validation.
type SAMLAdapter struct {
	providerName string
	sp           *saml.ServiceProvider
	cache        *ttlcache.Cache[string, domain.IdentityContext]
	logger       domain.Logger
}

// Config holds the parameters needed to construct a SAMLAdapter.
type Config struct {
	ProviderName string
	// MetadataURL is the URL of the IdP metadata XML document.
	MetadataURL string
	// SPEntityID is the entity ID of this service provider.
	SPEntityID string
	// ACSURL is the Assertion Consumer Service URL for this SP.
	ACSURL string
	// CertPath is the path to the SP's X.509 certificate PEM file.
	CertPath string
	// KeyPath is the path to the SP's RSA private key PEM file.
	KeyPath string
	// CacheTTL is how long a resolved IdentityContext is cached.
	// Defaults to 5 minutes if zero.
	CacheTTL time.Duration
}

// New constructs a SAMLAdapter from the given Config.
// It fetches the IdP metadata from MetadataURL and builds a crewjam ServiceProvider.
func New(cfg Config, logger domain.Logger) (*SAMLAdapter, error) {
	if cfg.ProviderName == "" {
		return nil, fmt.Errorf("saml: provider name is required")
	}
	if cfg.MetadataURL == "" {
		return nil, fmt.Errorf("saml: metadata URL is required")
	}
	if cfg.SPEntityID == "" {
		return nil, fmt.Errorf("saml: SP entity ID is required")
	}
	if cfg.ACSURL == "" {
		return nil, fmt.Errorf("saml: ACS URL is required")
	}

	// Load SP key pair if provided.
	var keyPair *tls.Certificate
	if cfg.CertPath != "" && cfg.KeyPath != "" {
		kp, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("saml: load SP key pair: %w", err)
		}
		keyPair = &kp
	}

	// Fetch IdP metadata.
	idpMeta, err := fetchIDPMetadata(cfg.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("saml: fetch IdP metadata from %s: %w", cfg.MetadataURL, err)
	}

	metaURL, err := url.Parse(cfg.SPEntityID)
	if err != nil {
		return nil, fmt.Errorf("saml: parse SP entity ID as URL: %w", err)
	}
	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse ACS URL: %w", err)
	}

	sp := &saml.ServiceProvider{
		EntityID:         cfg.SPEntityID,
		MetadataURL:      *metaURL,
		AcsURL:           *acsURL,
		IDPMetadata:      idpMeta,
		AllowIDPInitiated: true,
	}

	if keyPair != nil {
		rsaKey, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("saml: SP private key must be RSA")
		}
		sp.Key = rsaKey
		if len(keyPair.Certificate) > 0 {
			cert, err := x509.ParseCertificate(keyPair.Certificate[0])
			if err != nil {
				return nil, fmt.Errorf("saml: parse SP certificate: %w", err)
			}
			sp.Certificate = cert
		}
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	cache := ttlcache.New[string, domain.IdentityContext](
		ttlcache.WithTTL[string, domain.IdentityContext](cacheTTL),
	)
	go cache.Start()

	return &SAMLAdapter{
		providerName: cfg.ProviderName,
		sp:           sp,
		cache:        cache,
		logger:       logger,
	}, nil
}

// Resolve extracts the SAML assertion from ctx, validates it using crewjam/saml,
// and normalizes the attributes into a domain.IdentityContext.
// Returns domain.ErrUnauthenticated if no assertion is present,
// domain.ErrUnauthorized if the assertion is invalid,
// and domain.ErrServiceUnavailable if the IdP metadata endpoint is unreachable.
func (a *SAMLAdapter) Resolve(ctx context.Context) (domain.IdentityContext, error) {
	assertionXML, ok := authctx.SAMLAssertionFromContext(ctx)
	if !ok || strings.TrimSpace(assertionXML) == "" {
		return domain.IdentityContext{}, domain.ErrUnauthenticated
	}

	// Check cache first.
	if item := a.cache.Get(assertionXML); item != nil {
		return item.Value(), nil
	}

	// ParseXMLResponse validates signature, conditions, and audience.
	// We pass an empty possibleRequestIDs slice (IdP-initiated flow).
	acsURL, _ := url.Parse(a.sp.AcsURL.String())
	assertion, err := a.sp.ParseXMLResponse([]byte(assertionXML), nil, *acsURL)
	if err != nil {
		return domain.IdentityContext{}, fmt.Errorf("%w: %s", domain.ErrUnauthorized, err)
	}

	identity := a.normalizeAssertion(assertion)
	a.cache.Set(assertionXML, identity, ttlcache.DefaultTTL)

	a.logger.Debug("saml: resolved identity",
		"provider", a.providerName,
		"user_id", identity.UserID,
		"groups", identity.Groups,
	)

	return identity, nil
}

// Stop shuts down the background cache eviction goroutine.
func (a *SAMLAdapter) Stop() {
	a.cache.Stop()
}

// normalizeAssertion converts a crewjam Assertion into a domain.IdentityContext.
func (a *SAMLAdapter) normalizeAssertion(assertion *saml.Assertion) domain.IdentityContext {
	identity := domain.IdentityContext{
		Provider: a.providerName,
	}

	// Subject NameID → UserID.
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		identity.UserID = assertion.Subject.NameID.Value
	}

	// Walk attribute statements for well-known attributes.
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			values := attributeValues(attr)
			switch strings.ToLower(attr.Name) {
			case "email", "emailaddress",
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
				if len(values) > 0 {
					identity.Email = values[0]
				}
			case "groups", "group",
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
				"http://schemas.xmlsoap.org/claims/group":
				identity.Groups = append(identity.Groups, values...)
			case "entitlements", "entitlement":
				identity.Entitlements = append(identity.Entitlements, values...)
			}
		}
	}

	return identity
}

// samlAssertionFromContext retrieves the SAML assertion stored by authctx.WithSAMLAssertion.
func samlAssertionFromContext(ctx context.Context) (string, bool) {
	return authctx.SAMLAssertionFromContext(ctx)
}

// attributeValues extracts the string values from a SAML Attribute.
func attributeValues(attr saml.Attribute) []string {
	out := make([]string, 0, len(attr.Values))
	for _, v := range attr.Values {
		if s := strings.TrimSpace(v.Value); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// fetchIDPMetadata fetches and parses the IdP metadata XML from the given URL.
func fetchIDPMetadata(metadataURL string) (*saml.EntityDescriptor, error) {
	resp, err := http.Get(metadataURL) //nolint:gosec // URL comes from trusted config
	if err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrServiceUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: IdP metadata returned HTTP %d", domain.ErrServiceUnavailable, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read IdP metadata body: %w", err)
	}

	var meta saml.EntityDescriptor
	if err := xml.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("parse IdP metadata XML: %w", err)
	}

	return &meta, nil
}
