package bff

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"oidc-oauth2-idp/bff/internal/config"
	"oidc-oauth2-idp/bff/internal/session"
)

func TestCSRFMiddleware_RejectsInvalidToken(t *testing.T) {
	store := session.NewMemoryStore()
	manager := session.NewManager(store, "session", "01234567890123456789012345678901", true)
	var logs bytes.Buffer

	h := New(Dependencies{
		Logger:             slog.New(slog.NewJSONHandler(&logs, nil)),
		Sessions:           manager,
		AuthCodeURL:        func(_, _ string) string { return "" },
		ExchangeCode:       func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken:      func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		EndSessionEndpoint: "https://idp.example/logout",
		InsecureCookies:    true,
	})

	seed := httptest.NewRecorder()
	if err := manager.Create(seed, session.Session{
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(time.Hour),
		CSRFToken:   "expected-csrf",
		User:        session.UserClaims{Sub: "user-1"},
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := h.CSRFMiddleware(next)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", nil)
	req.Header.Set("X-CSRF-Token", "wrong-token")
	for _, c := range seed.Result().Cookies() {
		if c.Name == "session" {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	if !strings.Contains(logs.String(), "csrf_validation_failed") {
		t.Fatalf("expected csrf log event, got %s", logs.String())
	}
}

func TestSecurityHeaders_PresentOnAllResponses(t *testing.T) {
	h := New(Dependencies{
		Logger:                slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:              session.NewManager(session.NewMemoryStore(), "session", "01234567890123456789012345678901", true),
		AuthCodeURL:           func(_, _ string) string { return "" },
		ExchangeCode:          func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken:         func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		EndSessionEndpoint:    "https://idp.example/logout",
		ContentSecurityPolicy: config.DefaultContentSecurityPolicy,
		InsecureCookies:       true,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := h.SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Fatalf("unexpected HSTS header: %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("unexpected X-Content-Type-Options header: %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("unexpected X-Frame-Options header: %q", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != config.DefaultContentSecurityPolicy {
		t.Fatalf("unexpected CSP header: %q", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Fatalf("unexpected Referrer-Policy header: %q", got)
	}
}

func TestSecurityHeaders_UsesConfiguredCSPOverride(t *testing.T) {
	h := New(Dependencies{
		Logger:                slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:              session.NewManager(session.NewMemoryStore(), "session", "01234567890123456789012345678901", true),
		AuthCodeURL:           func(_, _ string) string { return "" },
		ExchangeCode:          func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken:         func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		EndSessionEndpoint:    "https://idp.example/logout",
		ContentSecurityPolicy: "default-src 'none'; script-src 'self'",
		InsecureCookies:       true,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := h.SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'none'; script-src 'self'" {
		t.Fatalf("unexpected CSP header override: %q", got)
	}
}

func TestTokenForwarder_InjectsAuthorizationFromSession(t *testing.T) {
	store := session.NewMemoryStore()
	manager := session.NewManager(store, "session", "01234567890123456789012345678901", true)

	h := New(Dependencies{
		Logger:             slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:           manager,
		AuthCodeURL:        func(_, _ string) string { return "" },
		ExchangeCode:       func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken:      func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		EndSessionEndpoint: "https://idp.example/logout",
		InsecureCookies:    true,
	})

	seed := httptest.NewRecorder()
	if err := manager.Create(seed, session.Session{
		AccessToken: "access-token-1",
		ExpiresAt:   time.Now().Add(time.Hour),
		CSRFToken:   "csrf-1",
		User:        session.UserClaims{Sub: "user-1"},
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer access-token-1" {
			t.Fatalf("expected Authorization header to be injected, got %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	wrapped := h.TokenForwarder(next)
	// API path should be forwarded
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	for _, c := range seed.Result().Cookies() {
		if c.Name == "session" {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}

func TestTokenForwarder_ReturnsUnauthorizedWithoutSession(t *testing.T) {
	h := New(Dependencies{
		Logger:             slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:           session.NewManager(session.NewMemoryStore(), "session", "01234567890123456789012345678901", true),
		AuthCodeURL:        func(_, _ string) string { return "" },
		ExchangeCode:       func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken:      func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		EndSessionEndpoint: "https://idp.example/logout",
		InsecureCookies:    true,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := h.TokenForwarder(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}
