package bff

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"oidc-oauth2-idp/bff/internal/session"
)

// SecurityHeaders sets baseline browser hardening headers for all BFF traffic.
// It is applied in BuildMiddlewareStack, so every request through the BFF gets
// the same CSP, frame, MIME sniffing, HSTS, and referrer protections.
// Keep this middleware first in the chain so even error responses carry headers.
func (h *Handler) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csp := strings.TrimSpace(h.deps.ContentSecurityPolicy)

		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// AuthGuard enforces session authentication for SPA route access.
// It runs in the global BFF middleware stack and redirects unauthenticated
// browser navigations to /login, while allowing auth, api, assets, health,
// and other explicitly public paths to pass through unchanged.
func (h *Handler) AuthGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/assets/") || r.URL.Path == "/login" || r.URL.Path == "/healthz" || r.URL.Path == "/favicon.ico" {
			next.ServeHTTP(w, r)
			return
		}

		_, ok, err := h.deps.Sessions.Get(r)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if !ok {
			h.deps.Logger.Info("auth_guard_redirect", "path", r.URL.Path, "remote_ip", r.RemoteAddr)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

const tokenRefreshThreshold = 60 * time.Second

func (h *Handler) refreshAccessToken(w http.ResponseWriter, r *http.Request, current session.Session) (session.Session, error) {
	newToken, err := h.deps.RefreshTokens(r.Context(), current.RefreshToken)
	if err != nil {
		return session.Session{}, err
	}
	updated := current
	updated.AccessToken = newToken.AccessToken
	updated.AccessTokenExpiry = newToken.Expiry
	if newToken.RefreshToken != "" {
		updated.RefreshToken = newToken.RefreshToken
	}
	if rawID, ok := newToken.Extra("id_token").(string); ok && rawID != "" {
		updated.IDToken = rawID
	}
	if err := h.deps.Sessions.Rotate(w, r, updated); err != nil {
		return session.Session{}, err
	}
	return updated, nil
}

// TokenForwarder injects a bearer token for internal API proxy requests.
// It is intended for /api/* traffic where the browser omits Authorization
// and the BFF should forward the logged-in session access token downstream.
// If no token is available in session, it returns 401 instead of proxying.
func (h *Handler) TokenForwarder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}

		current, ok, err := h.deps.Sessions.Get(r)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if !ok || strings.TrimSpace(current.AccessToken) == "" {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if h.deps.RefreshTokens != nil && current.RefreshToken != "" && !current.AccessTokenExpiry.IsZero() {
			tokenExpired := time.Now().After(current.AccessTokenExpiry)
			tokenNearExpiry := time.Now().Add(tokenRefreshThreshold).After(current.AccessTokenExpiry)
			if tokenExpired || tokenNearExpiry {
				refreshed, err := h.refreshAccessToken(w, r, current)
				if err != nil {
					if tokenExpired {
						_ = h.deps.Sessions.Destroy(w, r)
						writeJSONError(w, http.StatusUnauthorized, "session expired")
						return
					}
					h.deps.Logger.Warn("token_refresh_failed", "error", err.Error())
				} else {
					current = refreshed
				}
			}
		}

		forwarded := r.Clone(r.Context())
		forwarded.Header = r.Header.Clone()
		forwarded.Header.Set("Authorization", "Bearer "+current.AccessToken)
		next.ServeHTTP(w, forwarded)
	})
}

// CSRFMiddleware validates X-CSRF-Token for state-changing BFF endpoints.
// It runs in the shared middleware stack and only checks non-GET/HEAD/OPTIONS
// requests to /api/* and /auth/logout against the token stored in session.
// Failed validation is logged as a security event and rejected with 403.
func (h *Handler) CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/auth/logout") {
			next.ServeHTTP(w, r)
			return
		}

		current, ok, err := h.deps.Sessions.Get(r)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		headerToken := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
		if headerToken == "" || headerToken != current.CSRFToken {
			sub := ""
			if c, err := session.ParseIDTokenClaims(current.IDToken); err == nil {
				sub = c.Sub
			}
			h.deps.Logger.Info("security_event", "event", "csrf_validation_failed", "sub", sub, "path", r.URL.Path, "method", r.Method)
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
