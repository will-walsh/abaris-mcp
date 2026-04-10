//go:build integration

// Package saml_test contains integration tests for SAMLAdapter end-to-end
// with an in-process test IdP.
//
// These tests spin up a real httptest.Server that serves IdP metadata XML,
// generate a real RSA key pair for the test IdP, build a real crewjam/saml
// ServiceProvider, and mint real signed SAML responses.
//
// Run with: go test -tags integration ./internal/auth/saml/...
//
// Validates: Requirements 2.3, 2.4
package saml_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewsaml "github.com/crewjam/saml"
	"github.com/will-walsh/abaris-mcp/internal/auth/authctx"
	samlpkg "github.com/will-walsh/abaris-mcp/internal/auth/saml"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// ---------------------------------------------------------------------------
// Test IdP helpers
// ---------------------------------------------------------------------------

// testIdP holds the RSA key pair, self-signed certificate, and the
// httptest.Server that serves the IdP metadata XML.
type testIdP struct {
	server      *httptest.Server
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
	idp         *crewsaml.IdentityProvider
	// spMetadataFn is called by the ServiceProviderProvider to return SP metadata.
	// It is set after the SP is created.
	spMetadataFn func() *crewsaml.EntityDescriptor
}

// newTestIdP generates an RSA-2048 key pair, creates a self-signed certificate,
// starts an httptest.Server serving the IdP metadata, and returns the testIdP.
// The caller must call Close() when done.
func newTestIdP(t *testing.T) *testIdP {
	t.Helper()

	// Generate IdP RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate IdP RSA key: %v", err)
	}

	// Create a self-signed certificate for the IdP.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create IdP certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse IdP certificate: %v", err)
	}

	p := &testIdP{
		privateKey:  privateKey,
		certificate: cert,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		meta := p.idp.Metadata()
		w.Header().Set("Content-Type", "application/xml")
		if encErr := xml.NewEncoder(w).Encode(meta); encErr != nil {
			http.Error(w, "encode metadata: "+encErr.Error(), http.StatusInternalServerError)
		}
	})

	p.server = httptest.NewServer(mux)

	metaURL, _ := url.Parse(p.server.URL + "/metadata")
	ssoURL, _ := url.Parse(p.server.URL + "/sso")

	p.idp = &crewsaml.IdentityProvider{
		Key:         privateKey,
		Certificate: cert,
		MetadataURL: *metaURL,
		SSOURL:      *ssoURL,
		ServiceProviderProvider: &callbackSPProvider{
			fn: func() *crewsaml.EntityDescriptor {
				if p.spMetadataFn != nil {
					return p.spMetadataFn()
				}
				return nil
			},
		},
	}

	return p
}

// Close shuts down the test IdP server.
func (p *testIdP) Close() {
	p.server.Close()
}

// MetadataURL returns the metadata endpoint URL.
func (p *testIdP) MetadataURL() string {
	return p.server.URL + "/metadata"
}

// callbackSPProvider implements crewsaml.ServiceProviderProvider using a callback.
type callbackSPProvider struct {
	fn func() *crewsaml.EntityDescriptor
}

func (s *callbackSPProvider) GetServiceProvider(_ *http.Request, _ string) (*crewsaml.EntityDescriptor, error) {
	meta := s.fn()
	if meta == nil {
		return nil, fmt.Errorf("no SP metadata available")
	}
	return meta, nil
}

// ---------------------------------------------------------------------------
// SAML response minting helpers
// ---------------------------------------------------------------------------

// samlAssertionParams holds the parameters for minting a SAML assertion.
type samlAssertionParams struct {
	nameID       string
	email        string
	groups       []string
	entitlements []string
}

// mintSAMLResponseXML creates a real signed SAML response using the test IdP
// and returns the raw XML bytes of the signed <samlp:Response> element.
// These bytes are what the SAMLAdapter expects via authctx.WithSAMLAssertion.
func mintSAMLResponseXML(t *testing.T, idp *testIdP, sp *crewsaml.ServiceProvider, params samlAssertionParams) []byte {
	t.Helper()

	now := crewsaml.TimeNow()

	// Build the AuthnRequest fields needed by IdpAuthnRequest.
	// Use an empty ID so the response has no InResponseTo, enabling IdP-initiated flow
	// (the adapter calls ParseXMLResponse with nil possibleRequestIDs).
	issuer := crewsaml.Issuer{
		Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
		Value:  sp.MetadataURL.String(),
	}
	authnReq := crewsaml.AuthnRequest{
		ID:           "", // empty → response InResponseTo will be empty → IdP-initiated flow
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       &issuer,
		AssertionConsumerServiceURL: sp.AcsURL.String(),
	}

	// Find the SP's SSO descriptor and ACS endpoint from its metadata.
	spMeta := sp.Metadata()
	if len(spMeta.SPSSODescriptors) == 0 {
		t.Fatal("SP metadata has no SPSSODescriptors")
	}
	spssoDesc := spMeta.SPSSODescriptors[0]

	var acsEndpoint *crewsaml.IndexedEndpoint
	for i, acs := range spssoDesc.AssertionConsumerServices {
		if acs.Location == sp.AcsURL.String() {
			ep := spssoDesc.AssertionConsumerServices[i]
			acsEndpoint = &ep
			break
		}
	}
	if acsEndpoint == nil && len(spssoDesc.AssertionConsumerServices) > 0 {
		ep := spssoDesc.AssertionConsumerServices[0]
		acsEndpoint = &ep
	}
	if acsEndpoint == nil {
		t.Fatal("SP metadata has no ACS endpoints")
	}

	// Build custom attributes for email, groups and entitlements.
	// We use CustomAttributes so we can control the attribute names exactly as
	// the adapter's normalizeAssertion expects them.

	session := &crewsaml.Session{
		ID:         fmt.Sprintf("sess-%d", now.UnixNano()),
		CreateTime: now,
		ExpireTime: now.Add(time.Hour),
		NameID:     params.nameID,
		// Set email via CustomAttributes using the name the adapter recognises.
		// DefaultAssertionMaker sets email as urn:oid:0.9.2342.19200300.100.1.3 which
		// the adapter does not handle, so we inject it directly as "email".
		CustomAttributes: buildCustomAttributes(params),
	}

	// Directly construct IdpAuthnRequest (bypassing HTTP parsing).
	// We need a non-nil HTTPRequest because MakeAssertion accesses req.HTTPRequest.RemoteAddr.
	dummyReq, _ := http.NewRequest("POST", idp.idp.SSOURL.String(), nil)
	req := &crewsaml.IdpAuthnRequest{
		IDP:                     idp.idp,
		HTTPRequest:             dummyReq,
		Now:                     now,
		Request:                 authnReq,
		ServiceProviderMetadata: spMeta,
		SPSSODescriptor:         &spssoDesc,
		ACSEndpoint:             acsEndpoint,
	}

	assertionMaker := crewsaml.DefaultAssertionMaker{}
	if err := assertionMaker.MakeAssertion(req, session); err != nil {
		t.Fatalf("MakeAssertion: %v", err)
	}
	if err := req.MakeAssertionEl(); err != nil {
		t.Fatalf("MakeAssertionEl: %v", err)
	}
	if err := req.MakeResponse(); err != nil {
		t.Fatalf("MakeResponse: %v", err)
	}

	// Serialize the ResponseEl (an *etree.Element) to raw XML bytes.
	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize SAML response to XML: %v", err)
	}
	return xmlBytes
}

// ---------------------------------------------------------------------------
// Test adapter factory
// ---------------------------------------------------------------------------

// newIntegrationSAMLAdapter builds a SAMLAdapter pointed at the given test IdP.
// The SP entity ID and ACS URL are derived from the test server URL.
func newIntegrationSAMLAdapter(t *testing.T, idp *testIdP) (*samlpkg.SAMLAdapter, *crewsaml.ServiceProvider) {
	t.Helper()

	// Use fixed URLs for the SP — these don't need to be reachable, only consistent.
	spEntityID := "https://abaris.test/saml/metadata"
	acsURL := "https://abaris.test/saml/acs"

	// Build a crewsaml.ServiceProvider so we can mint assertions that the adapter will accept.
	spMetaURL, _ := url.Parse(spEntityID)
	spACSURL, _ := url.Parse(acsURL)
	sp := &crewsaml.ServiceProvider{
		EntityID:    spEntityID,
		MetadataURL: *spMetaURL,
		AcsURL:      *spACSURL,
		IDPMetadata: idp.idp.Metadata(),
	}

	// Register the SP metadata with the test IdP so it can mint assertions for it.
	idp.spMetadataFn = sp.Metadata

	cfg := samlpkg.Config{
		ProviderName: "test-saml",
		MetadataURL:  idp.MetadataURL(),
		SPEntityID:   spEntityID,
		ACSURL:       acsURL,
		CacheTTL:     time.Second,
	}
	adapter, err := samlpkg.New(cfg, noopLogger{})
	if err != nil {
		t.Fatalf("saml.New: %v", err)
	}
	return adapter, sp
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

// TestSAMLAdapter_Integration_ValidAssertion verifies that a valid, correctly-signed
// SAML response with all required attributes resolves to the expected IdentityContext.
//
// Validates: Requirements 2.3, 2.4
func TestSAMLAdapter_Integration_ValidAssertion(t *testing.T) {
	idp := newTestIdP(t)
	defer idp.Close()

	adapter, sp := newIntegrationSAMLAdapter(t, idp)
	defer adapter.Stop()

	responseXML := mintSAMLResponseXML(t, idp, sp, samlAssertionParams{
		nameID:       "user-saml-123",
		email:        "alice@example.com",
		groups:       []string{"developers", "admins"},
		entitlements: []string{"read", "write"},
	})

	ctx := authctx.WithSAMLAssertion(context.Background(), string(responseXML))
	identity, err := adapter.Resolve(ctx)
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}

	if identity.UserID != "user-saml-123" {
		t.Errorf("UserID: got %q, want %q", identity.UserID, "user-saml-123")
	}
	if identity.Email != "alice@example.com" {
		t.Errorf("Email: got %q, want %q", identity.Email, "alice@example.com")
	}
	if len(identity.Groups) != 2 || identity.Groups[0] != "developers" || identity.Groups[1] != "admins" {
		t.Errorf("Groups: got %v, want [developers admins]", identity.Groups)
	}
	if len(identity.Entitlements) != 2 || identity.Entitlements[0] != "read" || identity.Entitlements[1] != "write" {
		t.Errorf("Entitlements: got %v, want [read write]", identity.Entitlements)
	}
	if identity.Provider != "test-saml" {
		t.Errorf("Provider: got %q, want %q", identity.Provider, "test-saml")
	}
}

// TestSAMLAdapter_Integration_MissingAssertion verifies that a context with no
// SAML assertion returns ErrUnauthenticated.
//
// Validates: Requirements 2.3
func TestSAMLAdapter_Integration_MissingAssertion(t *testing.T) {
	idp := newTestIdP(t)
	defer idp.Close()

	adapter, _ := newIntegrationSAMLAdapter(t, idp)
	defer adapter.Stop()

	_, err := adapter.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error for missing assertion, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated for missing assertion, got: %v", err)
	}
}

// TestSAMLAdapter_Integration_MalformedAssertion verifies that a malformed
// (non-XML) assertion returns ErrUnauthorized.
//
// Validates: Requirements 2.3
func TestSAMLAdapter_Integration_MalformedAssertion(t *testing.T) {
	idp := newTestIdP(t)
	defer idp.Close()

	adapter, _ := newIntegrationSAMLAdapter(t, idp)
	defer adapter.Stop()

	ctx := authctx.WithSAMLAssertion(context.Background(), "this is not valid XML at all <<<>>>")
	_, err := adapter.Resolve(ctx)
	if err == nil {
		t.Fatal("expected error for malformed assertion, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for malformed assertion, got: %v", err)
	}
}

// TestSAMLAdapter_Integration_TamperedSignature verifies that a SAML response
// with a corrupted signature returns ErrUnauthorized.
//
// Validates: Requirements 2.3
func TestSAMLAdapter_Integration_TamperedSignature(t *testing.T) {
	idp := newTestIdP(t)
	defer idp.Close()

	adapter, sp := newIntegrationSAMLAdapter(t, idp)
	defer adapter.Stop()

	responseXML := mintSAMLResponseXML(t, idp, sp, samlAssertionParams{
		nameID: "user-tampered",
		email:  "tampered@example.com",
	})

	// Corrupt the XML by replacing a character in the middle of the signature.
	xmlStr := string(responseXML)
	corrupted := corruptXMLSignature(xmlStr)

	ctx := authctx.WithSAMLAssertion(context.Background(), corrupted)
	_, err := adapter.Resolve(ctx)
	if err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for tampered signature, got: %v", err)
	}
}

// TestSAMLAdapter_Integration_AttributesNormalization verifies that SAML attributes
// are correctly normalized into IdentityContext fields:
//   - NameID → UserID
//   - email attribute → Email
//   - groups attribute → Groups
//   - entitlements attribute → Entitlements
//
// Validates: Requirements 2.4
func TestSAMLAdapter_Integration_AttributesNormalization(t *testing.T) {
	idp := newTestIdP(t)
	defer idp.Close()

	adapter, sp := newIntegrationSAMLAdapter(t, idp)
	defer adapter.Stop()

	responseXML := mintSAMLResponseXML(t, idp, sp, samlAssertionParams{
		nameID:       "nameid-value-xyz",
		email:        "bob@corp.example",
		groups:       []string{"platform-eng", "sre"},
		entitlements: []string{"deploy", "rollback"},
	})

	ctx := authctx.WithSAMLAssertion(context.Background(), string(responseXML))
	identity, err := adapter.Resolve(ctx)
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}

	// NameID → UserID
	if identity.UserID != "nameid-value-xyz" {
		t.Errorf("UserID (from NameID): got %q, want %q", identity.UserID, "nameid-value-xyz")
	}
	// email → Email
	if identity.Email != "bob@corp.example" {
		t.Errorf("Email: got %q, want %q", identity.Email, "bob@corp.example")
	}
	// groups → Groups
	if len(identity.Groups) != 2 {
		t.Fatalf("Groups length: got %d, want 2", len(identity.Groups))
	}
	if identity.Groups[0] != "platform-eng" || identity.Groups[1] != "sre" {
		t.Errorf("Groups: got %v, want [platform-eng sre]", identity.Groups)
	}
	// entitlements → Entitlements
	if len(identity.Entitlements) != 2 {
		t.Fatalf("Entitlements length: got %d, want 2", len(identity.Entitlements))
	}
	if identity.Entitlements[0] != "deploy" || identity.Entitlements[1] != "rollback" {
		t.Errorf("Entitlements: got %v, want [deploy rollback]", identity.Entitlements)
	}
}

// TestSAMLAdapter_Integration_NoGroupsOrEntitlements verifies that a valid
// assertion with no groups or entitlements resolves without panicking.
//
// Validates: Requirements 2.4
func TestSAMLAdapter_Integration_NoGroupsOrEntitlements(t *testing.T) {
	idp := newTestIdP(t)
	defer idp.Close()

	adapter, sp := newIntegrationSAMLAdapter(t, idp)
	defer adapter.Stop()

	responseXML := mintSAMLResponseXML(t, idp, sp, samlAssertionParams{
		nameID: "minimal-user",
		email:  "minimal@example.com",
		// No groups or entitlements.
	})

	ctx := authctx.WithSAMLAssertion(context.Background(), string(responseXML))
	identity, err := adapter.Resolve(ctx)
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}

	if identity.UserID != "minimal-user" {
		t.Errorf("UserID: got %q, want %q", identity.UserID, "minimal-user")
	}
	if identity.Email != "minimal@example.com" {
		t.Errorf("Email: got %q, want %q", identity.Email, "minimal@example.com")
	}
	// Groups and Entitlements should be nil/empty — not a panic.
	_ = identity.Groups
	_ = identity.Entitlements
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// corruptXMLSignature corrupts a SAML response XML string by flipping a byte
// inside the first SignatureValue element, causing signature validation to fail.
func corruptXMLSignature(xmlStr string) string {
	const sigValueOpen = "<ds:SignatureValue>"
	const sigValueClose = "</ds:SignatureValue>"

	start := len(xmlStr)
	if idx := indexOf(xmlStr, sigValueOpen); idx >= 0 {
		start = idx + len(sigValueOpen)
	} else {
		// No signature found — just corrupt the middle of the string.
		mid := len(xmlStr) / 2
		runes := []rune(xmlStr)
		if mid < len(runes) {
			runes[mid] = 'X'
		}
		return string(runes)
	}

	end := indexOf(xmlStr[start:], sigValueClose)
	if end < 0 || end == 0 {
		// Can't find the closing tag — corrupt the middle.
		mid := len(xmlStr) / 2
		runes := []rune(xmlStr)
		if mid < len(runes) {
			runes[mid] = 'X'
		}
		return string(runes)
	}

	// Flip a byte in the middle of the signature value.
	sigValue := []byte(xmlStr[start : start+end])
	if len(sigValue) > 4 {
		sigValue[len(sigValue)/2] ^= 0xFF
	}
	return xmlStr[:start] + string(sigValue) + xmlStr[start+end:]
}

// indexOf returns the index of substr in s, or -1 if not found.
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// buildCustomAttributes builds the SAML attributes for a test assertion using
// attribute names that the SAMLAdapter's normalizeAssertion function recognises.
func buildCustomAttributes(params samlAssertionParams) []crewsaml.Attribute {
	var attrs []crewsaml.Attribute

	if params.email != "" {
		attrs = append(attrs, crewsaml.Attribute{
			Name:       "email",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []crewsaml.AttributeValue{
				{Type: "xs:string", Value: params.email},
			},
		})
	}

	if len(params.groups) > 0 {
		vals := make([]crewsaml.AttributeValue, len(params.groups))
		for i, g := range params.groups {
			vals[i] = crewsaml.AttributeValue{Type: "xs:string", Value: g}
		}
		attrs = append(attrs, crewsaml.Attribute{
			Name:       "groups",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     vals,
		})
	}

	if len(params.entitlements) > 0 {
		vals := make([]crewsaml.AttributeValue, len(params.entitlements))
		for i, e := range params.entitlements {
			vals[i] = crewsaml.AttributeValue{Type: "xs:string", Value: e}
		}
		attrs = append(attrs, crewsaml.Attribute{
			Name:       "entitlements",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     vals,
		})
	}

	return attrs
}
