package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func TestClientIDMetadataURLRejectsMalformedIdentifiers(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		clientID string
	}{
		{"userinfo", "https://user:pass@app.example/client.json"},
		{"userinfo without password", "https://user@app.example/client.json"},
		{"no path", "https://app.example"},
		{"bare root path", "https://app.example/"},
		{"dot segment", "https://app.example/./client.json"},
		{"dot dot segment", "https://app.example/a/../client.json"},
		{"fragment", "https://app.example/client.json#frag"},
		{"ftp scheme", "ftp://app.example/client.json"},
		{"urn", "urn:example:client"},
		{"opaque string", "client-1"},
		{"no host", "https:///client.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := clientIDMetadataURL(tc.clientID); err == nil {
				t.Fatalf("expected %q to be rejected as a client identifier URL", tc.clientID)
			}
		})
	}
}

func TestClientIDMetadataURLAcceptsValidIdentifiers(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		clientID string
	}{
		{"https", "https://app.example/oauth-client.json"},
		// The draft requires https. http is accepted as a documented deviation for
		// local testing, so it is pinned by a test and not only by a comment.
		{"http", "http://127.0.0.1:9000/client.json"},
		{"explicit port", "https://app.example:8443/client.json"},
		{"nested path", "https://app.example/a/b/client.json"},
		{"query", "https://app.example/client.json?v=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := clientIDMetadataURL(tc.clientID); err != nil {
				t.Fatalf("expected %q to be a client identifier URL: %v", tc.clientID, err)
			}
		})
	}
}

func TestClientIDMetadataURLWarnsOnQuery(t *testing.T) {
	t.Parallel()

	logs := &strings.Builder{}
	srv := &server{logger: newTestLogger(logs)}

	if !srv.isClientIDMetadataDocumentURL("https://app.example/client.json?v=2") {
		t.Fatalf("expected a query component to be accepted")
	}
	if !strings.Contains(logs.String(), "query component") {
		t.Fatalf("expected a warning about the query component, got %q", logs.String())
	}

	logs.Reset()
	if !srv.isClientIDMetadataDocumentURL("https://app.example/client.json") {
		t.Fatalf("expected a plain client identifier URL to be accepted")
	}
	if strings.Contains(logs.String(), "query component") {
		t.Fatalf("expected no warning without a query component, got %q", logs.String())
	}
}

func TestFetchClientIDMetadataRejectsBadResponses(t *testing.T) {
	t.Parallel()

	oversized := strings.Repeat("x", clientIDMetadataMaxBytes)

	for _, tc := range []struct {
		name    string
		handler func(w http.ResponseWriter, clientID string)
	}{
		{"non-200", func(w http.ResponseWriter, _ string) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"redirect not followed", func(w http.ResponseWriter, _ string) {
			w.Header().Set("Location", "https://elsewhere.example/client.json")
			w.WriteHeader(http.StatusFound)
		}},
		{"non-JSON content type", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, `{"client_id":%q}`, clientID)
		}},
		{"body over the size cap", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"client_name":%q}`, clientID, oversized)
		}},
		{"client_id mismatch", func(w http.ResponseWriter, _ string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"client_id":"https://other.example/client.json"}`)
		}},
		{"client_id missing", func(w http.ResponseWriter, _ string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"client_name":"demo"}`)
		}},
		{"client_secret present", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"client_secret":"s3cret"}`, clientID)
		}},
		{"client_secret_expires_at present", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"client_secret_expires_at":0}`, clientID)
		}},
		{"client_secret_basic", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`, clientID)
		}},
		{"client_secret_post", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_post"}`, clientID)
		}},
		{"client_secret_jwt", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_jwt"}`, clientID)
		}},
		{"private_key_jwt without keys", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}`, clientID)
		}},
		{"unsupported grant type", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"grant_types":["client_credentials"]}`, clientID)
		}},
		{"missing redirect_uris", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"grant_types":["authorization_code"]}`, clientID)
		}},
		{"relative redirect_uri", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["/callback"]}`, clientID)
		}},
		{"redirect_uri with fragment", func(w http.ResponseWriter, clientID string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"client_id":%q,"redirect_uris":["https://app.example/cb#x"]}`, clientID)
		}},
		{"not a JSON object", func(w http.ResponseWriter, _ string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `["not","a","document"]`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, clientID, _ := newMetadataDocumentServer(t, func(w http.ResponseWriter, clientID string) {
				tc.handler(w, clientID)
			})

			if _, err := srv.resolveClientIDMetadata(clientID); err == nil {
				t.Fatalf("expected %s to be rejected", tc.name)
			}
			srv.mu.Lock()
			cached := len(srv.clientIDMetadata)
			srv.mu.Unlock()
			if cached != 0 {
				t.Fatalf("expected a rejected document not to be cached, got %d entries", cached)
			}
		})
	}
}

func TestFetchClientIDMetadataAcceptsDocument(t *testing.T) {
	t.Parallel()

	srv, clientID, _ := newMetadataDocumentServer(t, func(w http.ResponseWriter, clientID string) {
		w.Header().Set("Content-Type", "application/client-metadata+json")
		_, _ = fmt.Fprintf(w, `{
			"client_id": %q,
			"client_name": "demo-app",
			"redirect_uris": ["https://app.example/callback"],
			"grant_types": ["authorization_code", "refresh_token"],
			"scope": "openid profile",
			"future_member_the_idp_does_not_model": {"nested": true}
		}`, clientID)
	})

	reg, err := srv.resolveClientIDMetadata(clientID)
	if err != nil {
		t.Fatalf("resolve metadata: %v", err)
	}
	if reg.RegistrationMethod != registrationMethodClientIDMetadataDocument {
		t.Fatalf("expected registration method %q, got %q", registrationMethodClientIDMetadataDocument, reg.RegistrationMethod)
	}
	if reg.ClientID != clientID {
		t.Fatalf("expected client_id %q, got %q", clientID, reg.ClientID)
	}
	// Absent token_endpoint_auth_method means "none" for a metadata document, not
	// the client_secret_basic that /register defaults to.
	if reg.TokenEndpointAuthMethod != "none" {
		t.Fatalf("expected token_endpoint_auth_method none, got %q", reg.TokenEndpointAuthMethod)
	}
	if reg.ClientName != "demo-app" {
		t.Fatalf("expected client_name demo-app, got %q", reg.ClientName)
	}

	srv.mu.Lock()
	stored, listed := srv.clients[clientID]
	srv.mu.Unlock()
	if !listed || stored.RegistrationMethod != registrationMethodClientIDMetadataDocument {
		t.Fatalf("expected the document to appear in the client registry, got %+v", stored)
	}
}

func TestCheckFetchAddressBlocksSpecialUseRanges(t *testing.T) {
	t.Parallel()

	for _, ip := range []string{
		"127.0.0.1", "::1",
		"10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "fe80::1",
		"224.0.0.1", "ff02::1", "ff01::1",
		"0.0.0.0", "::",
		"100.64.0.1", "192.0.0.1", "192.0.2.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "240.0.0.1", "255.255.255.255",
		"100::1", "2001:db8::1",
	} {
		t.Run(ip, func(t *testing.T) {
			t.Parallel()

			if err := checkFetchAddress(net.ParseIP(ip), false); err == nil {
				t.Fatalf("expected %s to be blocked", ip)
			}
		})
	}

	if err := checkFetchAddress(net.ParseIP("93.184.216.34"), false); err != nil {
		t.Fatalf("expected a public address to be allowed: %v", err)
	}
	if err := checkFetchAddress(nil, true); err == nil {
		t.Fatalf("expected a non-IP dial address to be refused")
	}
}

func TestCheckFetchAddressLoopbackAllowanceCoversOnlyLoopback(t *testing.T) {
	t.Parallel()

	if err := checkFetchAddress(net.ParseIP("127.0.0.1"), true); err != nil {
		t.Fatalf("expected loopback to be allowed with the exception on: %v", err)
	}
	// The exception is for loopback alone: everything else stays blocked either way.
	for _, ip := range []string{"10.0.0.1", "169.254.169.254", "192.0.2.1"} {
		if err := checkFetchAddress(net.ParseIP(ip), true); err == nil {
			t.Fatalf("expected %s to stay blocked with the loopback exception on", ip)
		}
	}
}

func TestMetadataFetchHonoursLoopbackAllowance(t *testing.T) {
	t.Parallel()

	srv, clientID, _ := newMetadataDocumentServer(t, serveMinimalDocument)

	srv.allowLoopbackMetadataFetch = false
	if _, err := srv.resolveClientIDMetadata(clientID); err == nil {
		t.Fatalf("expected a loopback fetch to be refused with the allowance off")
	}

	srv.allowLoopbackMetadataFetch = true
	if _, err := srv.resolveClientIDMetadata(clientID); err != nil {
		t.Fatalf("expected a loopback fetch to succeed with the allowance on: %v", err)
	}
}

func TestExternalURLIsLoopback(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		externalURL string
		want        bool
	}{
		{"http://127.0.0.1:5001", true},
		{"http://localhost:5001", true},
		{"http://[::1]:5001", true},
		{"https://idp.example.com", false},
		{"https://10.0.0.5:5001", false},
		{"", false},
	} {
		if got := externalURLIsLoopback(tc.externalURL); got != tc.want {
			t.Fatalf("externalURLIsLoopback(%q) = %v, want %v", tc.externalURL, got, tc.want)
		}
	}
}

func TestClientIDMetadataTTL(t *testing.T) {
	t.Parallel()

	srv := &server{clientIDMetadataTTL: 300 * time.Second}
	for _, tc := range []struct {
		cacheControl string
		want         time.Duration
	}{
		{"max-age=600", 600 * time.Second},
		{"public, max-age=600, must-revalidate", 600 * time.Second},
		{"max-age=1", clientIDMetadataMinTTL},
		{"max-age=999999", clientIDMetadataMaxTTL},
		{"no-store", 300 * time.Second},
		{"", 300 * time.Second},
		{"max-age=abc", 300 * time.Second},
	} {
		if got := srv.clientIDMetadataTTLFrom(tc.cacheControl); got != tc.want {
			t.Fatalf("ttl for %q = %v, want %v", tc.cacheControl, got, tc.want)
		}
	}

	// A server literal without a configured TTL still gets the documented default.
	if got := (&server{}).clientIDMetadataTTLFrom(""); got != clientIDMetadataDefaultTTL {
		t.Fatalf("default ttl = %v, want %v", got, clientIDMetadataDefaultTTL)
	}
}

func TestAuthorizeCachesMetadataDocument(t *testing.T) {
	t.Parallel()

	srv, clientID, fetches := newMetadataDocumentServer(t, serveMinimalDocument)
	srv.templates = testTemplates()
	srv.sessions = map[string]session{}
	srv.authContext = map[string]authContextEntry{}
	srv.codeMeta = map[string]codeMetadataEntry{}

	authorize := func() int {
		rec := httptest.NewRecorder()
		srv.authorize(rec, metadataAuthorizeRequest(clientID, "https://app.example/callback"))
		return rec.Code
	}

	if code := authorize(); code != http.StatusOK {
		t.Fatalf("first authorize: status %d", code)
	}
	if got := atomic.LoadInt32(fetches); got != 1 {
		t.Fatalf("expected 1 fetch, got %d", got)
	}

	if code := authorize(); code != http.StatusOK {
		t.Fatalf("second authorize: status %d", code)
	}
	if got := atomic.LoadInt32(fetches); got != 1 {
		t.Fatalf("expected the cached document to be reused, got %d fetches", got)
	}

	// Expire the entry in place rather than waiting out a TTL the clamp keeps above
	// a minute.
	srv.mu.Lock()
	entry := srv.clientIDMetadata[clientID]
	entry.expiresAt = time.Now().Add(-time.Second)
	srv.clientIDMetadata[clientID] = entry
	srv.mu.Unlock()

	if code := authorize(); code != http.StatusOK {
		t.Fatalf("third authorize: status %d", code)
	}
	if got := atomic.LoadInt32(fetches); got != 2 {
		t.Fatalf("expected an expired entry to be re-fetched, got %d fetches", got)
	}
}

func TestAuthorizeDoesNotCacheMetadataErrors(t *testing.T) {
	t.Parallel()

	var fetches int32
	var baseURL string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&fetches, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		serveMinimalDocument(w, baseURL+"/client.json")
	}))
	t.Cleanup(ts.Close)
	baseURL = ts.URL
	clientID := ts.URL + "/client.json"

	srv := &server{
		logger:                     newTestLogger(&strings.Builder{}),
		allowLoopbackMetadataFetch: true,
		clients:                    map[string]clientRegistration{},
		clientIDMetadata:           map[string]clientIDMetadataEntry{},
		sessions:                   map[string]session{},
		authContext:                map[string]authContextEntry{},
		codeMeta:                   map[string]codeMetadataEntry{},
		templates:                  testTemplates(),
	}

	rec := httptest.NewRecorder()
	srv.authorize(rec, metadataAuthorizeRequest(clientID, "https://app.example/callback"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected a failed fetch to abort with status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.authorize(rec, metadataAuthorizeRequest(clientID, "https://app.example/callback"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the retry to re-fetch and succeed, got status %d", rec.Code)
	}
	if got := atomic.LoadInt32(&fetches); got != 2 {
		t.Fatalf("expected the error response not to be cached, got %d fetches", got)
	}
}

func TestAuthorizeRegistersMetadataDocumentClient(t *testing.T) {
	t.Parallel()

	srv, clientID, _ := newMetadataDocumentServer(t, serveMinimalDocument)
	srv.templates = testTemplates()
	srv.sessions = map[string]session{}
	srv.authContext = map[string]authContextEntry{}
	srv.codeMeta = map[string]codeMetadataEntry{}

	rec := httptest.NewRecorder()
	srv.authorize(rec, metadataAuthorizeRequest(clientID, "https://app.example/callback"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	reg, ok := srv.clients[clientID]
	if !ok {
		t.Fatalf("expected %q to be registered", clientID)
	}
	if reg.RegistrationMethod != registrationMethodClientIDMetadataDocument {
		t.Fatalf("expected registration method %q, got %q", registrationMethodClientIDMetadataDocument, reg.RegistrationMethod)
	}
}

func TestAuthorizeRejectsUnregisteredRedirectURI(t *testing.T) {
	t.Parallel()

	srv, clientID, _ := newMetadataDocumentServer(t, serveMinimalDocument)
	srv.templates = testTemplates()
	srv.sessions = map[string]session{}
	srv.authContext = map[string]authContextEntry{}
	srv.codeMeta = map[string]codeMetadataEntry{}

	rec := httptest.NewRecorder()
	srv.authorize(rec, metadataAuthorizeRequest(clientID, "https://evil.example/callback"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	// An unregistered redirect URI must never be redirected to, not even to carry
	// the error.
	if location := rec.Header().Get("Location"); location != "" {
		t.Fatalf("expected no redirect, got Location %q", location)
	}
}

func TestAuthorizeRequiresPKCEForPublicMetadataDocumentClient(t *testing.T) {
	t.Parallel()

	srv, clientID, _ := newMetadataDocumentServer(t, serveMinimalDocument)
	srv.templates = testTemplates()
	srv.sessions = map[string]session{}
	srv.authContext = map[string]authContextEntry{}
	srv.codeMeta = map[string]codeMetadataEntry{}

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "https://app.example/callback")
	params.Set("scope", "openid")
	params.Set("response_type", "code")
	rec := httptest.NewRecorder()
	srv.authorize(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected a public client without PKCE to be rejected, got status %d", rec.Code)
	}
}

func TestAuthorizeEnforcesRedirectURIForDynamicClients(t *testing.T) {
	t.Parallel()

	// A behaviour change: a dynamically registered client used to be able to send
	// any redirect_uri at /authorize regardless of what it registered.
	srv := &server{
		logger:      newTestLogger(&strings.Builder{}),
		templates:   testTemplates(),
		sessions:    map[string]session{},
		authContext: map[string]authContextEntry{},
		codeMeta:    map[string]codeMetadataEntry{},
		clients: map[string]clientRegistration{
			"client-1": {
				ClientID:                "client-1",
				RedirectURIs:            []string{"http://localhost:8080/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
				RegistrationMethod:      registrationMethodDynamic,
			},
		},
	}

	rec := httptest.NewRecorder()
	srv.authorize(rec, metadataAuthorizeRequest("client-1", "http://localhost:9999/callback"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected an unregistered redirect_uri to be rejected, got status %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.authorize(rec, metadataAuthorizeRequest("client-1", "http://localhost:8080/callback"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the registered redirect_uri to be accepted, got status %d", rec.Code)
	}
}

func TestAuthorizeLeavesNonURLClientIDsOnTheAutomaticPath(t *testing.T) {
	t.Parallel()

	srv := &server{
		logger:      newTestLogger(&strings.Builder{}),
		externalURL: "http://127.0.0.1:5001",
		templates:   testTemplates(),
		sessions:    map[string]session{},
		authContext: map[string]authContextEntry{},
		codeMeta:    map[string]codeMetadataEntry{},
	}

	rec := httptest.NewRecorder()
	srv.authorize(rec, metadataAuthorizeRequest("client-1", "http://localhost:8080/callback"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected an opaque client_id to still be accepted, got status %d", rec.Code)
	}

	reg, ok := srv.clients["client-1"]
	if !ok || reg.RegistrationMethod != registrationMethodAutomatic {
		t.Fatalf("expected an automatic registration, got %+v", reg)
	}
}

func TestDiscoveryAdvertisesClientIDMetadataDocumentSupport(t *testing.T) {
	t.Parallel()

	srv := &server{externalURL: "http://127.0.0.1:5001", subjectType: "public"}
	rec := httptest.NewRecorder()
	srv.openidConfiguration(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	config := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &config); err != nil {
		t.Fatalf("unmarshal discovery document: %v", err)
	}
	if config["client_id_metadata_document_supported"] != true {
		t.Fatalf("expected client_id_metadata_document_supported, got %v", config["client_id_metadata_document_supported"])
	}
	if !discoveryListContains(config["token_endpoint_auth_methods_supported"], "private_key_jwt") {
		t.Fatalf("expected private_key_jwt among the token endpoint auth methods, got %v", config["token_endpoint_auth_methods_supported"])
	}
	for _, alg := range []string{"RS256", "ES256"} {
		if !discoveryListContains(config["token_endpoint_auth_signing_alg_values_supported"], alg) {
			t.Fatalf("expected %s among the signing algs, got %v", alg, config["token_endpoint_auth_signing_alg_values_supported"])
		}
	}
}

func TestRegisterStillRejectsPrivateKeyJWT(t *testing.T) {
	t.Parallel()

	// Discovery advertises private_key_jwt for metadata document clients, but
	// /register has no way to learn a client's public keys, so it must not start
	// accepting the method.
	srv := &server{logger: newTestLogger(&strings.Builder{}), clients: map[string]clientRegistration{}}
	rec := registerRequest(t, srv, `{"redirect_uris":["http://localhost:8080/callback"],"token_endpoint_auth_method":"private_key_jwt"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func discoveryListContains(value any, want string) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if text, ok := item.(string); ok && text == want {
			return true
		}
	}
	return false
}

// newMetadataDocumentServer stands up a live HTTP server serving a client ID
// metadata document at /client.json and returns an IdP wired to fetch it. The
// counter records how many times the document was requested.
//
// httptest listens on 127.0.0.1, which the SSRF guard blocks, so the loopback
// allowance is set directly on the server literal.
func newMetadataDocumentServer(t *testing.T, serve func(w http.ResponseWriter, clientID string)) (*server, string, *int32) {
	t.Helper()

	var fetches int32
	var clientID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetches, 1)
		serve(w, clientID)
	}))
	t.Cleanup(ts.Close)
	clientID = ts.URL + "/client.json"

	srv := &server{
		logger:                     newTestLogger(&strings.Builder{}),
		externalURL:                "http://127.0.0.1:5001",
		allowLoopbackMetadataFetch: true,
		clients:                    map[string]clientRegistration{},
		clientIDMetadata:           map[string]clientIDMetadataEntry{},
	}
	return srv, clientID, &fetches
}

// serveMinimalDocument writes the smallest document that completes an
// authorization code flow: a public client with one redirect URI.
func serveMinimalDocument(w http.ResponseWriter, clientID string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{
		"client_id": %q,
		"client_name": "demo-app",
		"redirect_uris": ["https://app.example/callback"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"scope": "openid"
	}`, clientID)
}

// metadataAuthorizeRequest builds an /authorize request carrying PKCE, which a
// public metadata document client is required to use.
func metadataAuthorizeRequest(clientID, redirectURI string) *http.Request {
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", "openid")
	params.Set("response_type", "code")
	params.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	params.Set("code_challenge_method", "S256")
	return httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
}

func newTestLogger(out *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// testTemplates provides the two pages /authorize can render, stripped to the
// fields the tests assert on.
func testTemplates() map[string]*template.Template {
	return map[string]*template.Template{
		"authenticate": template.Must(template.New("authenticate").Parse("{{.ReqID}}")),
		"error":        template.Must(template.New("error").Parse("{{.Text}}")),
	}
}

// testClientKey is the key a test client signs its assertions with. Generated
// once: an RSA key per subtest dominates the runtime of this file otherwise.
var testClientKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

func testClientJWKS(t *testing.T, kid string) json.RawMessage {
	t.Helper()

	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &testClientKey().PublicKey,
		KeyID:     kid,
		Algorithm: "RS256",
		Use:       "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal JWK set: %v", err)
	}
	return raw
}

// clientAssertionClaims builds a well-formed RFC 7523 assertion claim set that
// individual tests then break in one specific way.
func clientAssertionClaims(t *testing.T, clientID, audience string) jwt.MapClaims {
	t.Helper()

	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		t.Fatalf("generate jti: %v", err)
	}
	return jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"iat": time.Now().Add(-time.Second).Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
	}
}

func signClientAssertion(t *testing.T, key any, method jwt.SigningMethod, kid string, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign client assertion: %v", err)
	}
	return signed
}

// newPrivateKeyJWTServer builds a token exchange server whose client is
// registered from a metadata document and authenticates with private_key_jwt.
func newPrivateKeyJWTServer(t *testing.T, clientID string, reg clientRegistration) *server {
	t.Helper()

	srv := newTokenExchangeServer(t, clientID)
	srv.logger = newTestLogger(&strings.Builder{})
	srv.allowLoopbackMetadataFetch = true
	reg.ClientID = clientID
	reg.TokenEndpointAuthMethod = "private_key_jwt"
	reg.RegistrationMethod = registrationMethodClientIDMetadataDocument
	srv.clients[clientID] = reg
	// A live cache entry, as /authorize would have left behind. Without one the token
	// endpoint re-resolves the document, which for this fictitious client_id would
	// fail and mask whatever the test is actually about.
	srv.clientIDMetadata = map[string]clientIDMetadataEntry{
		clientID: {reg: reg, expiresAt: time.Now().Add(time.Hour)},
	}
	return srv
}

// privateKeyJWTTokenRequest exchanges the code seeded by newTokenExchangeServer,
// authenticating with an RFC 7523 client assertion.
func privateKeyJWTTokenRequest(t *testing.T, srv *server, assertion string) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {"code-1"},
		"redirect_uri":          {"http://localhost:8080/callback"},
		"client_assertion_type": {privateKeyJWTAssertionType},
		"client_assertion":      {assertion},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.token(rec, req)
	return rec
}

func TestTokenAcceptsPrivateKeyJWTWithInlineJwks(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{Jwks: testClientJWKS(t, "key-1")})

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	rec := privateKeyJWTTokenRequest(t, srv, assertion)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	tokens := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if accessToken, _ := tokens["access_token"].(string); accessToken == "" {
		t.Fatalf("expected an access token, got %v", tokens)
	}
}

func TestTokenAcceptsPrivateKeyJWTWithIssuerAudience(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{Jwks: testClientJWKS(t, "key-1")})

	// Plenty of client libraries send the issuer rather than the token endpoint.
	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
}

func TestTokenAcceptsPrivateKeyJWTWithoutKeyID(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{Jwks: testClientJWKS(t, "key-1")})

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
}

func TestTokenAcceptsPrivateKeyJWTWithFetchedJwksURI(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	jwks := testClientJWKS(t, "key-1")

	var fetches int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(ts.Close)

	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{JwksURI: ts.URL + "/jwks.json"})

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("expected the JWK set to be fetched once, got %d", got)
	}
}

func TestTokenRejectsPrivateKeyJWTWithBlockedJwksURI(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	// The cloud metadata service is the canonical SSRF target; the guard must refuse
	// it even though the loopback allowance is on.
	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{JwksURI: "http://169.254.169.254/jwks.json"})

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestTokenRejectsPrivateKeyJWTFailures(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	const audience = "http://127.0.0.1:5001/token"

	for _, tc := range []struct {
		name      string
		assertion func(t *testing.T) string
	}{
		{"missing assertion", func(*testing.T) string { return "" }},
		{"wrong audience", func(t *testing.T) string {
			claims := clientAssertionClaims(t, clientID, "https://other.example/token")
			return signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", claims)
		}},
		{"expired", func(t *testing.T) string {
			claims := clientAssertionClaims(t, clientID, audience)
			claims["exp"] = time.Now().Add(-10 * time.Minute).Unix()
			return signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", claims)
		}},
		{"no exp", func(t *testing.T) string {
			claims := clientAssertionClaims(t, clientID, audience)
			delete(claims, "exp")
			return signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", claims)
		}},
		{"exp beyond the bounded window", func(t *testing.T) string {
			claims := clientAssertionClaims(t, clientID, audience)
			claims["exp"] = time.Now().Add(24 * time.Hour).Unix()
			return signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", claims)
		}},
		{"no jti", func(t *testing.T) string {
			claims := clientAssertionClaims(t, clientID, audience)
			delete(claims, "jti")
			return signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", claims)
		}},
		{"wrong iss", func(t *testing.T) string {
			claims := clientAssertionClaims(t, clientID, audience)
			claims["iss"] = "https://other.example/client.json"
			return signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", claims)
		}},
		{"wrong sub", func(t *testing.T) string {
			claims := clientAssertionClaims(t, clientID, audience)
			claims["sub"] = "https://other.example/client.json"
			return signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", claims)
		}},
		{"wrong signing key", func(t *testing.T) string {
			other, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			return signClientAssertion(t, other, jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, audience))
		}},
		{"unknown kid", func(t *testing.T) string {
			return signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-2", clientAssertionClaims(t, clientID, audience))
		}},
		{"alg none", func(t *testing.T) string {
			return signClientAssertion(t, jwt.UnsafeAllowNoneSignatureType, jwt.SigningMethodNone, "key-1", clientAssertionClaims(t, clientID, audience))
		}},
		{"hmac", func(t *testing.T) string {
			// Signed with the public modulus an attacker can also read: rejecting HMAC
			// outright is what stops this being a valid signature.
			return signClientAssertion(t, testClientKey().N.Bytes(), jwt.SigningMethodHS256, "key-1", clientAssertionClaims(t, clientID, audience))
		}},
		{"not a JWT", func(*testing.T) string { return "not-a-jwt" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{Jwks: testClientJWKS(t, "key-1")})
			rec := privateKeyJWTTokenRequest(t, srv, tc.assertion(t))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected status %d, got %d: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTokenRejectsReplayedClientAssertion(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{Jwks: testClientJWKS(t, "key-1")})
	// A second code, because the first exchange consumes the one it is presented
	// with whether or not authentication succeeds.
	srv.codeMeta["code-2"] = codeMetadataEntry{CookieID: "cookie-1", ClientID: clientID}

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusOK {
		t.Fatalf("expected the first use to be accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	form := url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {"code-2"},
		"client_assertion_type": {privateKeyJWTAssertionType},
		"client_assertion":      {assertion},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.token(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected a replayed assertion to be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenRejectsPrivateKeyJWTForSecretClient(t *testing.T) {
	t.Parallel()

	// A dynamically registered client that registered with a secret cannot switch to
	// assertions: the method presented has to be the one it registered.
	srv := newTokenExchangeServer(t, "client-1")
	srv.logger = newTestLogger(&strings.Builder{})
	srv.clients["client-1"] = clientRegistration{
		ClientID:                "client-1",
		ClientSecret:            "s3cret",
		TokenEndpointAuthMethod: "client_secret_basic",
		RegistrationMethod:      registrationMethodDynamic,
	}

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, "client-1", srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestParseClientCredentialsReadsClientAssertion(t *testing.T) {
	t.Parallel()

	form := url.Values{
		"client_id":             {"https://app.example/client.json"},
		"client_assertion_type": {privateKeyJWTAssertionType},
		"client_assertion":      {"assertion-value"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}

	creds := parseClientCredentials(req)
	if creds.method != "private_key_jwt" {
		t.Fatalf("expected method private_key_jwt, got %q", creds.method)
	}
	if creds.assertion != "assertion-value" {
		t.Fatalf("expected the assertion to be carried, got %q", creds.assertion)
	}
	if creds.clientID != "https://app.example/client.json" {
		t.Fatalf("unexpected client_id %q", creds.clientID)
	}
}

// TestClientIDMetadataDocumentEndToEnd drives the whole flow the way a client
// does: publish a document, then /authorize, /login, /approve and /token against
// the routed IdP with the document URL as the client_id.
func TestClientIDMetadataDocumentEndToEnd(t *testing.T) {
	t.Parallel()

	templates, err := loadTemplates(filepath.Join("kodata", "templates"))
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv := &server{
		logger:                     newTestLogger(&strings.Builder{}),
		subjectType:                "public",
		accessTokenLifetime:        300,
		refreshTokenLifetime:       3600,
		allowLoopbackMetadataFetch: true,
		clients:                    map[string]clientRegistration{},
		clientIDMetadata:           map[string]clientIDMetadataEntry{},
		sessions:                   map[string]session{},
		authContext:                map[string]authContextEntry{},
		codeMeta:                   map[string]codeMetadataEntry{},
		templates:                  templates,
		privateKey:                 key,
		publicKey:                  &key.PublicKey,
	}
	idp := httptest.NewServer(newMux(srv))
	t.Cleanup(idp.Close)
	srv.externalURL = idp.URL

	jwks := testClientJWKS(t, "key-1")
	var clientID string
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=600")
		_, _ = fmt.Fprintf(w, `{
			"client_id": %q,
			"client_name": "metadata-demo",
			"redirect_uris": ["https://app.example/callback"],
			"grant_types": ["authorization_code"],
			"response_types": ["code"],
			"scope": "openid",
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks": %s
		}`, clientID, jwks)
	}))
	t.Cleanup(app.Close)
	clientID = app.URL + "/client.json"

	// Redirects are followed manually so the authorization code can be read off the
	// Location header rather than chased to an unreachable app.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authorizeParams := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"https://app.example/callback"},
		"scope":                 {"openid"},
		"response_type":         {"code"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	authorizeResp, err := client.Get(idp.URL + "/authorize?" + authorizeParams.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	reqID := extractFormValue(t, readAllString(t, authorizeResp), "reqid")

	loginResp, err := client.PostForm(idp.URL+"/login", url.Values{
		"reqid":    {reqID},
		"username": {"alice"},
		"password": {"valid"},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginBody := readAllString(t, loginResp)

	approveResp, err := client.PostForm(idp.URL+"/approve", url.Values{
		"reqid":                    {reqID},
		"approve":                  {"approve"},
		"id_token_claims_json":     {extractTextarea(t, loginBody, "id_token_claims_json")},
		"access_token_claims_json": {extractTextarea(t, loginBody, "access_token_claims_json")},
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	defer func() { _ = approveResp.Body.Close() }()

	location, err := url.Parse(approveResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse approve redirect %q: %v", approveResp.Header.Get("Location"), err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("expected an authorization code in %q", approveResp.Header.Get("Location"))
	}

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, idp.URL+"/token"))
	tokenResp, err := client.PostForm(idp.URL+"/token", url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {"https://app.example/callback"},
		"code_verifier":         {codeVerifier},
		"client_assertion_type": {privateKeyJWTAssertionType},
		"client_assertion":      {assertion},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	body := readAllString(t, tokenResp)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, tokenResp.StatusCode, body)
	}

	tokens := map[string]any{}
	if err := json.Unmarshal([]byte(body), &tokens); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if accessToken, _ := tokens["access_token"].(string); accessToken == "" {
		t.Fatalf("expected an access token, got %v", tokens)
	}
	if idToken, _ := tokens["id_token"].(string); idToken == "" {
		t.Fatalf("expected an ID token, got %v", tokens)
	}

	listing, err := client.Get(idp.URL + "/clients")
	if err != nil {
		t.Fatalf("get clients: %v", err)
	}
	page := readAllString(t, listing)
	for _, want := range []string{clientID, "registration method: client_id_metadata_document", "metadata-demo"} {
		if !strings.Contains(page, want) {
			t.Fatalf("expected the clients page to contain %q", want)
		}
	}
}

func readAllString(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(body)
}

func extractFormValue(t *testing.T, page, name string) string {
	t.Helper()

	match := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`).FindStringSubmatch(page)
	if match == nil {
		t.Fatalf("no form field %q in page", name)
	}
	return match[1]
}

func extractTextarea(t *testing.T, page, name string) string {
	t.Helper()

	match := regexp.MustCompile(`(?s)name="` + regexp.QuoteMeta(name) + `"[^>]*>(.*?)</textarea>`).FindStringSubmatch(page)
	if match == nil {
		t.Fatalf("no textarea %q in page", name)
	}
	return html.UnescapeString(match[1])
}

// testRotatedClientKey is the key a client rotates *to*. Kept alongside
// testClientKey so that a revocation test costs no extra RSA generation.
var testRotatedClientKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// jwksFor renders a one-key JWK set, leaving "use" and "alg" off when empty so
// that the unrestricted case can be expressed too.
func jwksFor(t *testing.T, key *rsa.PrivateKey, kid, use, alg string) json.RawMessage {
	t.Helper()

	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &key.PublicKey,
		KeyID:     kid,
		Algorithm: alg,
		Use:       use,
	}}})
	if err != nil {
		t.Fatalf("marshal JWK set: %v", err)
	}
	return raw
}

func TestTokenRejectsClientAssertionSignedByAnEncryptionKey(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{
		Jwks: jwksFor(t, testClientKey(), "key-1", "enc", ""),
	})

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected a key published for encryption to be refused, got status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenRejectsClientAssertionUsingAnAlgorithmTheKeyIsNotFor(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{
		Jwks: jwksFor(t, testClientKey(), "key-1", "sig", "RS256"),
	})

	// Same modulus, different algorithm than the one the client pinned the key to.
	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodPS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected a PS256 assertion against an RS256-pinned key to be refused, got status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenAcceptsClientAssertionAgainstAnUnrestrictedKey(t *testing.T) {
	t.Parallel()

	const clientID = "https://app.example/client.json"
	srv := newPrivateKeyJWTServer(t, clientID, clientRegistration{
		Jwks: jwksFor(t, testClientKey(), "key-1", "", ""),
	})

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodPS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusOK {
		t.Fatalf("expected a key stating neither use nor alg to be usable, got status %d: %s", rec.Code, rec.Body.String())
	}
}

// newExpiredMetadataTokenServer seeds a token exchange for a metadata document
// client whose cached document has already aged out, so that the token endpoint
// has to go back to the origin.
func newExpiredMetadataTokenServer(t *testing.T, authMethod string, document func(w http.ResponseWriter, clientID string)) (*server, string) {
	t.Helper()

	var clientID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		document(w, clientID)
	}))
	t.Cleanup(ts.Close)
	clientID = ts.URL + "/client.json"

	srv := newTokenExchangeServer(t, clientID)
	srv.logger = newTestLogger(&strings.Builder{})
	srv.allowLoopbackMetadataFetch = true

	stale := clientRegistration{
		ClientID:                clientID,
		RedirectURIs:            []string{"http://localhost:8080/callback"},
		TokenEndpointAuthMethod: authMethod,
		RegistrationMethod:      registrationMethodClientIDMetadataDocument,
		Jwks:                    testClientJWKS(t, "key-1"),
	}
	srv.clients[clientID] = stale
	srv.clientIDMetadata = map[string]clientIDMetadataEntry{
		clientID: {reg: stale, expiresAt: time.Now().Add(-time.Minute)},
	}
	return srv, clientID
}

func TestTokenRejectsAssertionSignedByAWithdrawnKey(t *testing.T) {
	t.Parallel()

	// The client rotated its key. Only /authorize used to re-read the document, so a
	// refresh or a code exchange kept honouring the key the client had withdrawn.
	srv, clientID := newExpiredMetadataTokenServer(t, "private_key_jwt", func(w http.ResponseWriter, clientID string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"client_id": %q,
			"redirect_uris": ["http://localhost:8080/callback"],
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks": %s
		}`, clientID, jwksFor(t, testRotatedClientKey(), "key-2", "sig", "RS256"))
	})

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected the withdrawn key to be refused, got status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenAcceptsAssertionSignedByTheRotatedKey(t *testing.T) {
	t.Parallel()

	srv, clientID := newExpiredMetadataTokenServer(t, "private_key_jwt", func(w http.ResponseWriter, clientID string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"client_id": %q,
			"redirect_uris": ["http://localhost:8080/callback"],
			"token_endpoint_auth_method": "private_key_jwt",
			"jwks": %s
		}`, clientID, jwksFor(t, testRotatedClientKey(), "key-2", "sig", "RS256"))
	})

	assertion := signClientAssertion(t, testRotatedClientKey(), jwt.SigningMethodRS256, "key-2", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusOK {
		t.Fatalf("expected the rotated key to be accepted, got status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenFailsClosedWhenAConfidentialClientsDocumentIsUnreachable(t *testing.T) {
	t.Parallel()

	srv, clientID := newExpiredMetadataTokenServer(t, "private_key_jwt", func(w http.ResponseWriter, _ string) {
		http.Error(w, "gone", http.StatusInternalServerError)
	})

	assertion := signClientAssertion(t, testClientKey(), jwt.SigningMethodRS256, "key-1", clientAssertionClaims(t, clientID, srv.externalURL+"/token"))
	if rec := privateKeyJWTTokenRequest(t, srv, assertion); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected an unreadable document to refuse the client, got status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenFailsOpenWhenAPublicClientsDocumentIsUnreachable(t *testing.T) {
	t.Parallel()

	// A public client proves nothing at this endpoint, so an origin outage must not
	// turn into an outage for the client.
	srv, _ := newExpiredMetadataTokenServer(t, "none", func(w http.ResponseWriter, _ string) {
		http.Error(w, "gone", http.StatusInternalServerError)
	})

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"code-1"},
		"redirect_uri": {"http://localhost:8080/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.token(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected a public client to be served, got status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthorizeDefaultsCodeChallengeMethodToPlain(t *testing.T) {
	t.Parallel()

	// RFC 7636 section 4.3: an omitted method means "plain". Left unset it used to
	// reach /token as an empty string and be rejected there as invalid_grant.
	srv, clientID, _ := newMetadataDocumentServer(t, serveMinimalDocument)
	srv.templates = testTemplates()
	srv.sessions = map[string]session{}
	srv.authContext = map[string]authContextEntry{}
	srv.codeMeta = map[string]codeMetadataEntry{}

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "https://app.example/callback")
	params.Set("scope", "openid")
	params.Set("response_type", "code")
	params.Set("code_challenge", "a-plain-verifier")
	rec := httptest.NewRecorder()
	srv.authorize(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var stored string
	for _, ctx := range srv.authContext {
		stored = ctx.CodeChallengeMethod
	}
	if stored != "plain" {
		t.Fatalf("expected the stored code_challenge_method to be %q, got %q", "plain", stored)
	}
}

func TestAuthorizeRejectsUnsupportedCodeChallengeMethod(t *testing.T) {
	t.Parallel()

	srv, clientID, _ := newMetadataDocumentServer(t, serveMinimalDocument)
	srv.templates = testTemplates()
	srv.sessions = map[string]session{}
	srv.authContext = map[string]authContextEntry{}
	srv.codeMeta = map[string]codeMetadataEntry{}

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", "https://app.example/callback")
	params.Set("scope", "openid")
	params.Set("response_type", "code")
	params.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	params.Set("code_challenge_method", "S512")
	rec := httptest.NewRecorder()
	srv.authorize(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected an unsupported method to be refused at /authorize, got status %d", rec.Code)
	}
}

func TestMetadataFetchRetainsNoConnections(t *testing.T) {
	t.Parallel()

	// Each fetch builds its own transport, so a pooled connection would be held by a
	// transport nobody can reach again - a descriptor leaked per fetch, and one an
	// unauthenticated /authorize can drive. Observed at the origin rather than
	// through the transport, because the leak is precisely that nothing holds a
	// reference to ask.
	var mu sync.Mutex
	open := map[net.Conn]bool{}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	ts.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		mu.Lock()
		defer mu.Unlock()
		switch state {
		case http.StateNew:
			open[conn] = true
		case http.StateClosed, http.StateHijacked:
			delete(open, conn)
		}
	}
	ts.Start()
	t.Cleanup(ts.Close)

	srv := &server{logger: newTestLogger(&strings.Builder{}), allowLoopbackMetadataFetch: true}

	const fetches = 3
	for i := 0; i < fetches; i++ {
		if _, _, err := srv.fetchGuardedJSON(ts.URL); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}

	// The close is the client's to initiate, so the origin learns of it a moment
	// later. Poll rather than sleep a fixed amount.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		remaining := len(open)
		mu.Unlock()
		if remaining == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected every connection to be released after %d fetches, %d still open", fetches, remaining)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
