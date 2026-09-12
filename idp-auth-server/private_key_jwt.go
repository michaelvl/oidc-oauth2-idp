package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// privateKeyJWTAssertionType is the RFC 7523 section 2.2 client assertion type. A
// token request carrying it is authenticating with private_key_jwt.
const privateKeyJWTAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

const (
	// privateKeyJWTMaxLifetime bounds how far ahead an assertion may expire. The
	// replay cache has to hold every jti until its assertion expires, so an
	// unbounded exp would be an unbounded memory commitment handed to the client.
	privateKeyJWTMaxLifetime = 10 * time.Minute

	// privateKeyJWTLeeway absorbs clock skew between the client and this IdP.
	privateKeyJWTLeeway = 60 * time.Second
)

// privateKeyJWTAlgorithms are the asymmetric signature algorithms accepted on a
// client assertion. Passing them to the parser is what rejects "none" and every
// HMAC algorithm: with a JWK set as the verification key, an HMAC assertion would
// otherwise be checked against a public key the attacker also has.
var privateKeyJWTAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// advertisedTokenEndpointAuthSigningAlgs is the discovery-facing subset: the
// algorithms a client is likely to pick, rather than everything the parser
// tolerates.
var advertisedTokenEndpointAuthSigningAlgs = []string{"RS256", "ES256"}

// clientKeySet is a client's published JWK set, as resolved from an inline jwks or
// a fetched jwks_uri.
type clientKeySet struct {
	keys *jose.JSONWebKeySet
}

// verifyPrivateKeyJWT authenticates a token request that presented an RFC 7523
// client assertion. clientID is the identity the grant established, never
// anything the request claimed for itself.
//
// Resolving the key set may fetch a jwks_uri, so this must run with s.mu
// released.
func (s *server) verifyPrivateKeyJWT(clientID string, reg clientRegistration, assertion string) error {
	if assertion == "" {
		return errors.New("client_assertion is missing")
	}

	keySet, err := s.clientKeySet(clientID, reg)
	if err != nil {
		return err
	}

	claims := jwt.MapClaims{}
	_, err = jwt.NewParser(
		jwt.WithValidMethods(privateKeyJWTAlgorithms),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(privateKeyJWTLeeway),
	).ParseWithClaims(assertion, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		return keySet.verificationKeys(kid, token.Method.Alg())
	})
	if err != nil {
		return fmt.Errorf("client assertion is not valid: %w", err)
	}

	issuer, _ := claims["iss"].(string)
	if issuer != clientID {
		return fmt.Errorf("client assertion iss is %q, want %q", issuer, clientID)
	}
	subject, _ := claims["sub"].(string)
	if subject != clientID {
		return fmt.Errorf("client assertion sub is %q, want %q", subject, clientID)
	}

	// RFC 7523 section 3 names the token endpoint as the audience. The issuer URL is
	// accepted too because a good many client libraries send that instead.
	if !audContains(claims, s.externalURL+"/token") && !audContains(claims, s.externalURL) {
		return fmt.Errorf("client assertion aud %v contains neither %q nor %q", claims["aud"], s.externalURL+"/token", s.externalURL)
	}

	expiry, err := claims.GetExpirationTime()
	if err != nil || expiry == nil {
		return errors.New("client assertion has no usable exp")
	}
	if expiry.After(time.Now().Add(privateKeyJWTMaxLifetime)) {
		return fmt.Errorf("client assertion expires more than %s in the future", privateKeyJWTMaxLifetime)
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return errors.New("client assertion has no jti")
	}
	return s.consumePrivateKeyJWTJTI(clientID, jti, expiry.Time)
}

// consumePrivateKeyJWTJTI records a jti and rejects one already seen. The record
// is kept only until the assertion it belongs to expires, and expired records are
// pruned on the way past - consistent with the rest of this IdP's state, which
// does not survive a restart either.
func (s *server) consumePrivateKeyJWTJTI(clientID, jti string, expiry time.Time) error {
	key := clientID + "\x00" + jti

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.privateKeyJWTJTIs == nil {
		s.privateKeyJWTJTIs = map[string]time.Time{}
	}
	now := time.Now()
	for seen, seenExpiry := range s.privateKeyJWTJTIs {
		if now.After(seenExpiry) {
			delete(s.privateKeyJWTJTIs, seen)
		}
	}
	if _, replayed := s.privateKeyJWTJTIs[key]; replayed {
		return fmt.Errorf("client assertion jti %q has already been used", jti)
	}
	s.privateKeyJWTJTIs[key] = expiry.Add(privateKeyJWTLeeway)
	return nil
}

// clientKeySet resolves the client's published keys, preferring an inline jwks and
// falling back to fetching jwks_uri through the SSRF-guarded client. For a client
// registered from a metadata document the result is cached alongside the document
// and therefore discarded when the document expires, so a key rotation is picked
// up on the next refresh.
func (s *server) clientKeySet(clientID string, reg clientRegistration) (*clientKeySet, error) {
	s.mu.Lock()
	entry, cached := s.clientIDMetadata[clientID]
	s.mu.Unlock()
	if cached && entry.keys != nil && time.Now().Before(entry.expiresAt) {
		return entry.keys, nil
	}

	var raw []byte
	switch {
	case len(reg.Jwks) > 0:
		raw = reg.Jwks
	case reg.JwksURI != "":
		fetched, _, err := s.fetchGuardedJSON(reg.JwksURI)
		if err != nil {
			return nil, fmt.Errorf("fetching jwks_uri failed: %w", err)
		}
		raw = fetched
	default:
		return nil, errors.New("client publishes neither jwks nor jwks_uri")
	}

	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("client JWK set is not valid: %w", err)
	}
	if len(keys.Keys) == 0 {
		return nil, errors.New("client JWK set is empty")
	}
	resolved := &clientKeySet{keys: &keys}

	// Stored back only onto a live cache entry: a client whose document has expired
	// in the meantime should re-resolve its keys along with the rest of it.
	s.mu.Lock()
	if entry, ok := s.clientIDMetadata[clientID]; ok && time.Now().Before(entry.expiresAt) {
		entry.keys = resolved
		s.clientIDMetadata[clientID] = entry
	}
	s.mu.Unlock()

	return resolved, nil
}

// verificationKeys returns the candidate keys for an assertion, narrowed to the
// header's kid when it carries one. A kid naming a key the client does not publish
// is an error rather than a reason to try the rest.
//
// alg is the algorithm the assertion header declared. It is already known to be one
// of privateKeyJWTAlgorithms; it is passed here so that a key the client restricted
// to some other algorithm is not pressed into service for this one.
func (c *clientKeySet) verificationKeys(kid, alg string) (jwt.VerificationKeySet, error) {
	candidates := c.keys.Keys
	if kid != "" {
		candidates = c.keys.Key(kid)
		if len(candidates) == 0 {
			return jwt.VerificationKeySet{}, fmt.Errorf("client JWK set has no key with kid %q", kid)
		}
	}

	out := jwt.VerificationKeySet{}
	for _, candidate := range candidates {
		// JWK "use" and "alg" are the client's own statement of what each key is for
		// (RFC 7517 sections 4.2 and 4.4). Both are optional, so an absent value means
		// unrestricted - but a stated one is honoured: an encryption key must not
		// double as a signature verification key, and a key pinned to RS256 must not
		// verify a PS256 assertion made with the same modulus.
		if candidate.Use != "" && candidate.Use != "sig" {
			continue
		}
		if candidate.Algorithm != "" && candidate.Algorithm != alg {
			continue
		}
		// Only asymmetric keys can verify a client assertion. A symmetric key in a
		// published set would be a shared secret the whole world has.
		switch key := candidate.Public().Key.(type) {
		case *rsa.PublicKey:
			out.Keys = append(out.Keys, key)
		case *ecdsa.PublicKey:
			out.Keys = append(out.Keys, key)
		}
	}
	if len(out.Keys) == 0 {
		return jwt.VerificationKeySet{}, fmt.Errorf("client JWK set has no usable RSA or EC public key for alg %q", alg)
	}
	return out, nil
}
