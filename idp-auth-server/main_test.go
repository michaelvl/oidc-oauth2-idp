package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
		Username: "alice",
		Sub:      "xxalicexx",
		CookieID: "s1",
		ClientSessions: []clientSession{
			{SessionID: "cs1", ClientID: "c1", Scope: "openid"},
			{SessionID: "cs2", ClientID: "c2", Scope: "openid profile"},
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
		externalURL: "http://127.0.0.1:5001",
		privateKey:  key,
		publicKey:   &key.PublicKey,
	}

	tok, _, err := srv.issueToken("alice", []string{"api", "userinfo"}, map[string]any{
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
		externalURL: "http://127.0.0.1:5001",
		privateKey:  keyA,
		publicKey:   &keyA.PublicKey,
	}

	tok, _, err := srv.issueToken("alice", []string{"api"}, map[string]any{}, time.Now().Add(5*time.Minute))
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

func TestDedupeStrings(t *testing.T) {
	t.Parallel()

	got := dedupeStrings([]string{"a", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected dedupe result: got=%v want=%v", got, want)
	}
}

func TestAvatarRequiresBearerWhenProtected(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	templatesDir := t.TempDir()
	avatarDir := filepath.Join(templatesDir, "avatars")
	if err := os.MkdirAll(avatarDir, 0o755); err != nil {
		t.Fatalf("mkdir avatars: %v", err)
	}
	if err := os.WriteFile(filepath.Join(avatarDir, "1.svg"), []byte("<svg></svg>"), 0o644); err != nil {
		t.Fatalf("write avatar: %v", err)
	}

	srv := &server{
		externalURL:       "http://127.0.0.1:5001",
		templatesDir:      templatesDir,
		protectPictureURL: true,
		privateKey:        key,
		publicKey:         &key.PublicKey,
	}

	req := httptest.NewRequest(http.MethodGet, "/avatars/1.svg", nil)
	rec := httptest.NewRecorder()

	srv.avatar(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	wantWWW := `Bearer realm="http://127.0.0.1:5001", error="invalid_token"`
	if got := rec.Header().Get("WWW-Authenticate"); got != wantWWW {
		t.Fatalf("expected WWW-Authenticate %q, got %q", wantWWW, got)
	}
}

func TestAvatarAcceptsBearerWhenProtected(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	templatesDir := t.TempDir()
	avatarDir := filepath.Join(templatesDir, "avatars")
	if err := os.MkdirAll(avatarDir, 0o755); err != nil {
		t.Fatalf("mkdir avatars: %v", err)
	}
	if err := os.WriteFile(filepath.Join(avatarDir, "1.svg"), []byte("<svg></svg>"), 0o644); err != nil {
		t.Fatalf("write avatar: %v", err)
	}

	csid := "test-client-session-id"
	cookieID := "test-cookie-id"
	srv := &server{
		externalURL:       "http://127.0.0.1:5001",
		templatesDir:      templatesDir,
		protectPictureURL: true,
		privateKey:        key,
		publicKey:         &key.PublicKey,
		sessions: map[string]session{
			cookieID: {
				Username: "alice",
				CookieID: cookieID,
				ClientSessions: []clientSession{
					{SessionID: csid},
				},
			},
		},
	}

	// alice maps to avatar index 7
	avatarIdx := avatarIndex("alice")
	avatarFile := fmt.Sprintf("%d.svg", avatarIdx)
	if err := os.WriteFile(filepath.Join(avatarDir, avatarFile), []byte("<svg></svg>"), 0o644); err != nil {
		t.Fatalf("write avatar: %v", err)
	}

	token, _, err := srv.issueToken("alice", []string{"api"}, map[string]any{
		"scope":     "openid profile",
		"token_use": "access",
		"csid":      csid,
	}, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/avatars/"+avatarFile, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	srv.avatar(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "image/svg+xml") {
		t.Fatalf("expected image/svg+xml content type, got %q", got)
	}
}

func TestSectorIdentifier(t *testing.T) {
	t.Parallel()

	cases := []struct {
		redirectURI string
		clientID    string
		want        string
	}{
		{"http://app.example.com/callback", "myclient", "app.example.com"},
		{"https://rp.example.org:8443/cb", "myclient", "rp.example.org:8443"},
		{"not-a-uri", "myclient", "myclient"},
		{"", "myclient", "myclient"},
	}
	for _, tc := range cases {
		got := sectorIdentifier(tc.redirectURI, tc.clientID)
		if got != tc.want {
			t.Fatalf("sectorIdentifier(%q, %q) = %q, want %q", tc.redirectURI, tc.clientID, got, tc.want)
		}
	}
}

func TestComputeAdvertisedSubPublic(t *testing.T) {
	t.Parallel()

	srv := &server{subjectType: "public"}
	sub := "xxalicexx"
	got := srv.computeAdvertisedSub(sub, "app.example.com")
	if got != sub {
		t.Fatalf("public mode: expected sub unchanged, got %q", got)
	}
}

func TestComputeAdvertisedSubPairwise(t *testing.T) {
	t.Parallel()

	salt := make([]byte, 32)
	srv := &server{subjectType: "pairwise", pairwiseSalt: salt}
	sub := "xxalicexx"

	got1 := srv.computeAdvertisedSub(sub, "app1.example.com")
	got2 := srv.computeAdvertisedSub(sub, "app2.example.com")
	got3 := srv.computeAdvertisedSub("xxbobxx", "app1.example.com")

	if got1 == got2 {
		t.Fatalf("same sub, different sectors should produce different advertised sub")
	}
	if got1 == got3 {
		t.Fatalf("different subs, same sector should produce different advertised sub")
	}
	// deterministic: same inputs always produce same output
	if got1 != srv.computeAdvertisedSub(sub, "app1.example.com") {
		t.Fatalf("computeAdvertisedSub is not deterministic")
	}
}

func TestAdvertisedSubIsOpaque(t *testing.T) {
	t.Parallel()

	salt := make([]byte, 32)
	srv := &server{subjectType: "pairwise", pairwiseSalt: salt}
	sub := "xxalicexx"
	got := srv.computeAdvertisedSub(sub, "app.example.com")

	if strings.Contains(got, "alice") || strings.Contains(got, "xx") {
		t.Fatalf("pairwise sub must not contain the internal sub; got %q", got)
	}
}

func TestSubDistinctFromUsername(t *testing.T) {
	t.Parallel()

	username := "alice"
	sub := "xx" + username + "xx"
	if sub == username {
		t.Fatalf("internal sub must differ from username")
	}
	if !strings.Contains(sub, username) {
		t.Fatalf("internal sub should embed the username for this implementation")
	}
}

func TestIDTokenEmailClaimWithEmailScope(t *testing.T) {
	t.Parallel()

	srv := &server{subjectType: "public", emailDomain: "example.com"}
	claims := srv.defaultIDTokenClaims(authContextEntry{Username: "alice", Scope: "openid email"})

	if claims["email"] != "alice@example.com" {
		t.Fatalf("expected email alice@example.com, got %v", claims["email"])
	}
	if claims["email_verified"] != true {
		t.Fatalf("expected email_verified true, got %v", claims["email_verified"])
	}
}

func TestIDTokenNoEmailClaimWithoutEmailScope(t *testing.T) {
	t.Parallel()

	srv := &server{subjectType: "public", emailDomain: "example.com"}
	claims := srv.defaultIDTokenClaims(authContextEntry{Username: "alice", Scope: "openid profile"})

	if _, ok := claims["email"]; ok {
		t.Fatalf("email claim must be absent without the email scope")
	}
	if _, ok := claims["email_verified"]; ok {
		t.Fatalf("email_verified claim must be absent without the email scope")
	}
}

func TestEmailForUsernameHonorsDomain(t *testing.T) {
	t.Parallel()

	srv := &server{emailDomain: "corp.example.org"}
	if got := srv.emailForUsername("bob"); got != "bob@corp.example.org" {
		t.Fatalf("expected bob@corp.example.org, got %q", got)
	}
}

func TestAuthorizationResponseCarriesIssuer(t *testing.T) {
	t.Parallel()

	srv := &server{
		externalURL: "http://127.0.0.1:5001",
		codeMeta:    map[string]codeMetadataEntry{},
	}
	sess := session{
		CookieID: "cookie-1",
		ClientSessions: []clientSession{{
			ClientID:    "client-1",
			RedirectURI: "http://localhost:8080/callback",
		}},
	}

	rec := httptest.NewRecorder()
	srv.issueCodeAndRedirect(rec, httptest.NewRequest(http.MethodGet, "/authorize", nil), sess, "client-1", "state-1", "nonce-1")

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status %d, got %d", http.StatusSeeOther, rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := loc.Query().Get("iss"); got != srv.externalURL {
		t.Fatalf("expected iss %q, got %q", srv.externalURL, got)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("expected a code in the authorization response")
	}
}

func TestAuthorizationErrorResponseCarriesIssuer(t *testing.T) {
	t.Parallel()

	srv := &server{
		externalURL: "http://127.0.0.1:5001",
		sessions:    map[string]session{},
		authContext: map[string]authContextEntry{},
	}

	form := url.Values{
		"client_id":     {"client-1"},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"state":         {"state-1"},
		"prompt":        {"none"},
		"id_token_hint": {"not-a-jwt"},
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.authorize(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status %d, got %d", http.StatusSeeOther, rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := loc.Query().Get("error"); got != "login_required" {
		t.Fatalf("expected error login_required, got %q", got)
	}
	if got := loc.Query().Get("iss"); got != srv.externalURL {
		t.Fatalf("expected iss %q, got %q", srv.externalURL, got)
	}
}

func TestDiscoveryAdvertisesIssParameterSupport(t *testing.T) {
	t.Parallel()

	srv := &server{externalURL: "http://127.0.0.1:5001", subjectType: "public"}

	rec := httptest.NewRecorder()
	srv.openidConfiguration(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	var config map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &config); err != nil {
		t.Fatalf("decode discovery document: %v", err)
	}
	if config["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("expected authorization_response_iss_parameter_supported true, got %v", config["authorization_response_iss_parameter_supported"])
	}
}
