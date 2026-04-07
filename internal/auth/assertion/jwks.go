package assertion

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// jwks is the JSON Web Key Set structure returned by the JWKS endpoint.
type jwks struct {
	Keys []jwk `json:"keys"`
}

// jwk is a single JSON Web Key (RSA public key in JWK format, RFC 7517).
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n"` // base64url-encoded modulus
	E   string `json:"e"` // base64url-encoded exponent
}

// buildJWKS converts an *rsa.PublicKey into a JWKS document.
func buildJWKS(pub *rsa.PublicKey, kid string) jwks {
	// Encode modulus and exponent as base64url (no padding).
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	key := jwk{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
	return jwks{Keys: []jwk{key}}
}
