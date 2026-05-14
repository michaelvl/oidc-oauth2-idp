package bff

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"oidc-oauth2-idp/bff/internal/session"
)

func TestAPIProxy_ForwardsRequestAndInjectsBearer(t *testing.T) {
	var got struct {
		Method string
		Path   string
		Query  string
		Auth   string
		Body   string
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Method = r.Method
		got.Path = r.URL.Path
		got.Query = r.URL.RawQuery
		got.Auth = r.Header.Get("Authorization")
		got.Body = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	manager, cookie := seededSessionManager(t, "access-token-1")
	proxy, err := NewAPIProxy(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), manager, upstream.URL)
	if err != nil {
		t.Fatalf("new api proxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects?q=abc", bytes.NewBufferString(`{"x":1}`))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got.Method != http.MethodPost {
		t.Fatalf("expected method POST, got %q", got.Method)
	}
	if got.Path != "/api/v1/projects" {
		t.Fatalf("expected path /api/v1/projects, got %q", got.Path)
	}
	if got.Query != "q=abc" {
		t.Fatalf("expected query q=abc, got %q", got.Query)
	}
	if got.Auth != "Bearer access-token-1" {
		t.Fatalf("expected bearer header, got %q", got.Auth)
	}
	if got.Body != `{"x":1}` {
		t.Fatalf("expected body to be forwarded, got %q", got.Body)
	}
}

func TestAPIProxy_ReturnsUnauthorizedWithoutSession(t *testing.T) {
	manager := session.NewManager(session.NewMemoryStore(), "session", "01234567890123456789012345678901", true)
	proxy, err := NewAPIProxy(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), manager, "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("new api proxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAPIProxy_ReturnsBadGatewayWhenUpstreamFails(t *testing.T) {
	manager, cookie := seededSessionManager(t, "access-token-1")
	proxy, err := NewAPIProxy(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), manager, "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("new api proxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "bad gateway" {
		t.Fatalf("expected bad gateway payload, got %#v", body)
	}
}

func TestStaticAssetsProxy_ForwardsRootPath(t *testing.T) {
	gotPath := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("index"))
	}))
	defer upstream.Close()

	proxy, err := NewStaticAssetsProxy(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), upstream.URL)
	if err != nil {
		t.Fatalf("new static assets proxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if gotPath != "/" {
		t.Fatalf("expected / path, got %q", gotPath)
	}
	if rec.Body.String() != "index" {
		t.Fatalf("expected response body to be forwarded, got %q", rec.Body.String())
	}
}

func TestStaticAssetsProxy_RequiresBaseURL(t *testing.T) {
	_, err := NewStaticAssetsProxy(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), "")
	if err == nil {
		t.Fatal("expected error when STATIC_ASSETS_BASE_URL is missing")
	}
}

func seededSessionManager(t *testing.T, accessToken string) (*session.Manager, *http.Cookie) {
	t.Helper()
	manager := session.NewManager(session.NewMemoryStore(), "session", "01234567890123456789012345678901", true)
	seed := httptest.NewRecorder()
	if err := manager.Create(seed, session.Session{
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(time.Hour),
		CSRFToken:   "csrf",
		User:        session.UserClaims{Sub: "sub-1"},
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	for _, c := range seed.Result().Cookies() {
		if c.Name == "session" {
			return manager, c
		}
	}
	t.Fatal("expected session cookie")
	return nil, nil
}
