package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildURL(t *testing.T) {
	t.Parallel()

	got := buildURL("http://localhost:8080/callback", map[string]string{
		"code":  "abc123",
		"state": "xyz",
	})

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse result URL: %v", err)
	}

	if u.Scheme != "http" || u.Host != "localhost:8080" || u.Path != "/callback" {
		t.Fatalf("unexpected URL base: %s", got)
	}

	q := u.Query()
	if q.Get("code") != "abc123" {
		t.Fatalf("expected code query param")
	}
	if q.Get("state") != "xyz" {
		t.Fatalf("expected state query param")
	}
}

func TestAudContains(t *testing.T) {
	t.Parallel()

	claimsSingle := map[string]any{"aud": "http://issuer"}
	if !audContains(claimsSingle, "http://issuer") {
		t.Fatalf("expected single audience match")
	}

	claimsList := map[string]any{"aud": []any{"a", "b", "c"}}
	if !audContains(claimsList, "b") {
		t.Fatalf("expected list audience match")
	}
	if audContains(claimsList, "missing") {
		t.Fatalf("did not expect missing audience match")
	}
}

func TestIntFromAny(t *testing.T) {
	t.Parallel()

	if got := intFromAny(float64(42), 7); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
	if got := intFromAny(11, 7); got != 11 {
		t.Fatalf("expected 11, got %d", got)
	}
	if got := intFromAny(int64(13), 7); got != 13 {
		t.Fatalf("expected 13, got %d", got)
	}
	if got := intFromAny("bad", 7); got != 7 {
		t.Fatalf("expected default 7, got %d", got)
	}
}

func TestCapitalize(t *testing.T) {
	t.Parallel()

	if got := capitalize("alice"); got != "Alice" {
		t.Fatalf("expected Alice, got %q", got)
	}
	if got := capitalize("ALICE"); got != "Alice" {
		t.Fatalf("expected Alice, got %q", got)
	}
	if got := capitalize(""); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestGetClientSessionByID(t *testing.T) {
	t.Parallel()

	sess := session{
		Subject:   "alice",
		SessionID: "s1",
		ClientSessions: []clientSession{
			{ClientID: "c1", Scope: "openid"},
			{ClientID: "c2", Scope: "openid profile"},
		},
	}

	cs := getClientSessionByID(sess, "c2")
	if cs == nil {
		t.Fatalf("expected client session")
	}
	if cs.Scope != "openid profile" {
		t.Fatalf("unexpected scope: %s", cs.Scope)
	}

	if got := getClientSessionByID(sess, "missing"); got != nil {
		t.Fatalf("expected nil for missing client session")
	}
}

func TestIssueAndDecodeToken(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv := &server{
		ownBaseURL: "http://127.0.0.1:5001",
		privateKey: key,
		publicKey:  &key.PublicKey,
	}

	tok, err := srv.issueToken("alice", []string{"api", "userinfo"}, map[string]any{
		"scope":     "openid profile",
		"token_use": "access",
	}, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	claims, err := srv.decodeJWT(tok, srv.publicKey)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}

	if claims["sub"] != "alice" {
		t.Fatalf("expected sub alice, got %v", claims["sub"])
	}
	if claims["iss"] != "http://127.0.0.1:5001" {
		t.Fatalf("unexpected issuer: %v", claims["iss"])
	}
	if claims["scope"] != "openid profile" {
		t.Fatalf("unexpected scope: %v", claims["scope"])
	}

	aud, ok := claims["aud"].([]any)
	if !ok {
		t.Fatalf("expected aud as []any, got %T", claims["aud"])
	}
	wantAud := []any{"api", "userinfo"}
	if !reflect.DeepEqual(aud, wantAud) {
		t.Fatalf("unexpected aud: %#v", aud)
	}
}

func TestDecodeJWTRejectsWrongKey(t *testing.T) {
	t.Parallel()

	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	srv := &server{
		ownBaseURL: "http://127.0.0.1:5001",
		privateKey: keyA,
		publicKey:  &keyA.PublicKey,
	}

	tok, err := srv.issueToken("alice", []string{"api"}, map[string]any{}, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	if _, err := srv.decodeJWT(tok, &keyB.PublicKey); err == nil {
		t.Fatalf("expected decode to fail with wrong key")
	}
}

func TestPKCES256ComputationMatchesExpected(t *testing.T) {
	t.Parallel()

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	if challenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("unexpected PKCE challenge: %s", challenge)
	}
}

func TestBuildURLHandlesInvalidBase(t *testing.T) {
	t.Parallel()

	base := "://bad-url"
	got := buildURL(base, map[string]string{"k": "v"})
	if got != base {
		t.Fatalf("expected invalid base passthrough, got %q", got)
	}
}

func TestDecodeJWTRejectsMalformedToken(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv := &server{publicKey: &key.PublicKey}
	_, err = srv.decodeJWT("not-a-jwt", srv.publicKey)
	if err == nil {
		t.Fatalf("expected malformed token error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected token-related error, got %v", err)
	}
}
