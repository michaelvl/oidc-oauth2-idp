package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"oidc-oauth2-idp/bff/internal/session"
)

func testIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal id token claims: %v", err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestAuthCallback_SetsSessionAndCSRFCookie(t *testing.T) {
	store := session.NewMemoryStore()
	manager := session.NewManager(store, "session", "01234567890123456789012345678901", true)

	h := New(Dependencies{
		Logger:      slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:    manager,
		AuthCodeURL: func(state, _ string) string { return "https://idp.example/auth?state=" + state },
		ExchangeCode: func(_ context.Context, code, _ string) (*oauth2.Token, error) {
			if code != "valid-code" {
				t.Fatalf("unexpected code: %s", code)
			}
			return &oauth2.Token{AccessToken: "access", RefreshToken: "refresh", Expiry: time.Now().Add(1 * time.Hour)}, nil
		},
		VerifyIDToken: func(_ context.Context, raw string) (session.UserClaims, error) {
			if raw != "" {
				t.Fatalf("expected empty raw id token in test, got: %s", raw)
			}
			return session.UserClaims{Sub: "user-1", Name: "User", Email: "user@example.com", Picture: "https://example.com/u.png"}, nil
		},
		EndSessionEndpoint: "https://idp.example/logout",
		InsecureCookies:    true,
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=valid-code&state=test-state", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "test-state"})
	req.AddCookie(&http.Cookie{Name: verifierCookieName, Value: "test-verifier"})
	rec := httptest.NewRecorder()

	h.Callback(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status %d, got %d", http.StatusSeeOther, rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("expected redirect to /, got %q", got)
	}

	cookies := rec.Result().Cookies()
	var foundSession, foundCSRF bool
	for _, c := range cookies {
		if c.Name == "session" {
			foundSession = true
			if !c.HttpOnly {
				t.Fatal("expected session cookie to be HttpOnly")
			}
		}
		if c.Name == csrfCookieName {
			foundCSRF = true
			if c.HttpOnly {
				t.Fatal("expected csrf cookie to be readable by JS")
			}
		}
	}

	if !foundSession {
		t.Fatal("expected session cookie to be set")
	}
	if !foundCSRF {
		t.Fatal("expected csrf_token cookie to be set")
	}
}

func TestAuthCallback_RejectsDuplicateStateBeforeTokenExchange(t *testing.T) {
	store := session.NewMemoryStore()
	manager := session.NewManager(store, "session", "01234567890123456789012345678901", true)

	exchangeCalls := 0
	h := New(Dependencies{
		Logger:      slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:    manager,
		AuthCodeURL: func(state, _ string) string { return "https://idp.example/auth?state=" + state },
		ExchangeCode: func(_ context.Context, code, _ string) (*oauth2.Token, error) {
			exchangeCalls++
			if code != "duplicate-code" {
				t.Fatalf("unexpected code: %s", code)
			}
			return &oauth2.Token{AccessToken: "access", RefreshToken: "refresh", Expiry: time.Now().Add(1 * time.Hour)}, nil
		},
		VerifyIDToken: func(_ context.Context, raw string) (session.UserClaims, error) {
			if raw != "" {
				t.Fatalf("expected empty raw id token in test, got: %s", raw)
			}
			return session.UserClaims{Sub: "user-1"}, nil
		},
		InsecureCookies: true,
	})

	req1 := httptest.NewRequest(http.MethodGet, "/auth/callback?code=duplicate-code&state=shared-state", nil)
	req1.AddCookie(&http.Cookie{Name: stateCookieName, Value: "shared-state"})
	req1.AddCookie(&http.Cookie{Name: verifierCookieName, Value: "test-verifier"})
	rec1 := httptest.NewRecorder()
	h.Callback(rec1, req1)

	if rec1.Code != http.StatusSeeOther {
		t.Fatalf("expected first callback status %d, got %d", http.StatusSeeOther, rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/auth/callback?code=duplicate-code&state=shared-state", nil)
	req2.AddCookie(&http.Cookie{Name: stateCookieName, Value: "shared-state"})
	req2.AddCookie(&http.Cookie{Name: verifierCookieName, Value: "test-verifier"})
	rec2 := httptest.NewRecorder()
	h.Callback(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected second callback status %d, got %d", http.StatusUnauthorized, rec2.Code)
	}

	if exchangeCalls != 1 {
		t.Fatalf("expected token exchange to be called once, got %d", exchangeCalls)
	}
}

func TestAuthLogin_RedirectsToOIDCProvider(t *testing.T) {
	h := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions: session.NewManager(session.NewMemoryStore(), "session", "01234567890123456789012345678901", true),
		AuthCodeURL: func(state, verifier string) string {
			if state == "" || verifier == "" {
				t.Fatal("expected state and verifier")
			}
			return "https://idp.example/auth"
		},
		ExchangeCode:       func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken:      func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		EndSessionEndpoint: "https://idp.example/logout",
		InsecureCookies:    true,
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected status %d, got %d", http.StatusSeeOther, rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://idp.example/auth" {
		t.Fatalf("expected redirect to idp, got %q", got)
	}
}

func TestAuthMe_ReturnsClaimsWhenAuthenticated(t *testing.T) {
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
		AccessToken: "token",
		IDToken:     testIDToken(t, map[string]any{"sub": "abc", "name": "Alice", "email": "alice@example.com", "picture": "https://example.com/a.png"}),
		CSRFToken:   "csrf",
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	for _, c := range seed.Result().Cookies() {
		if c.Name == "session" {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()

	h.Me(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["sub"] != "abc" || body["email"] != "alice@example.com" {
		t.Fatalf("unexpected body: %+v", body)
	}
	if body["picture"] != "/auth/avatar" {
		t.Fatalf("expected proxied picture path, got %q", body["picture"])
	}
}

func TestAuthMe_Returns401WhenNoSession(t *testing.T) {
	h := New(Dependencies{
		Logger:             slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:           session.NewManager(session.NewMemoryStore(), "session", "01234567890123456789012345678901", true),
		AuthCodeURL:        func(_, _ string) string { return "" },
		ExchangeCode:       func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken:      func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		EndSessionEndpoint: "https://idp.example/logout",
		InsecureCookies:    true,
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rec := httptest.NewRecorder()

	h.Me(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAuthLogout_DestroysSessionAndRedirects(t *testing.T) {
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
	if err := manager.Create(seed, session.Session{AccessToken: "token", IDToken: "raw.id.token", CSRFToken: "csrf"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("X-CSRF-Token", "csrf")
	for _, c := range seed.Result().Cookies() {
		if c.Name == "session" {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()

	h.Logout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	want := "https://idp.example/logout?id_token_hint=raw.id.token"
	if got := body["redirectTo"]; got != want {
		t.Fatalf("expected redirectTo %q, got %q", want, got)
	}
}

func TestAuthAvatar_ProxiesWithAccessToken(t *testing.T) {
	store := session.NewMemoryStore()
	manager := session.NewManager(store, "session", "01234567890123456789012345678901", true)

	avatarUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Fatalf("expected bearer token to be forwarded, got %q", got)
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "private, max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<svg></svg>")
	}))
	defer avatarUpstream.Close()

	h := New(Dependencies{
		Logger:           slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:         manager,
		AuthCodeURL:      func(_, _ string) string { return "" },
		ExchangeCode:     func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken:    func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		AvatarHTTPClient: avatarUpstream.Client(),
		InsecureCookies:  true,
	})

	seed := httptest.NewRecorder()
	if err := manager.Create(seed, session.Session{
		AccessToken: "access-token",
		IDToken:     testIDToken(t, map[string]any{"sub": "abc", "picture": avatarUpstream.URL + "/avatar.svg"}),
		CSRFToken:   "csrf",
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/avatar", nil)
	for _, c := range seed.Result().Cookies() {
		if c.Name == "session" {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()

	h.Avatar(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "image/svg+xml" {
		t.Fatalf("expected content type to be preserved, got %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, max-age=60" {
		t.Fatalf("expected cache control to be preserved, got %q", got)
	}
	if got := rec.Body.String(); got != "<svg></svg>" {
		t.Fatalf("unexpected body %q", got)
	}
}

func TestAuthAvatar_Returns404WhenNoPicture(t *testing.T) {
	store := session.NewMemoryStore()
	manager := session.NewManager(store, "session", "01234567890123456789012345678901", true)
	h := New(Dependencies{
		Logger:        slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Sessions:      manager,
		AuthCodeURL:   func(_, _ string) string { return "" },
		ExchangeCode:  func(context.Context, string, string) (*oauth2.Token, error) { return nil, nil },
		VerifyIDToken: func(context.Context, string) (session.UserClaims, error) { return session.UserClaims{}, nil },
		InsecureCookies: true,
	})

	seed := httptest.NewRecorder()
	if err := manager.Create(seed, session.Session{AccessToken: "token", IDToken: testIDToken(t, map[string]any{"sub": "sub-1"}), CSRFToken: "csrf"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/avatar", nil)
	for _, c := range seed.Result().Cookies() {
		if c.Name == "session" {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()

	h.Avatar(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}
