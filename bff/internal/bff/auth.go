package bff

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"

	"oidc-oauth2-idp/bff/internal/session"
)

const (
	stateCookieName    = "oidc_state"
	verifierCookieName = "oidc_verifier"
	csrfCookieName     = "csrf_token"
)

type Dependencies struct {
	Logger             *slog.Logger
	Sessions           *session.Manager
	AuthCodeURL        func(state, codeVerifier string) string
	ExchangeCode       func(ctx context.Context, code, verifier string) (*oauth2.Token, error)
	VerifyIDToken      func(ctx context.Context, rawIDToken string) (session.UserClaims, error)
	EndSessionEndpoint string
	AvatarHTTPClient   *http.Client
	InsecureCookies    bool
}

type Handler struct {
	deps Dependencies
}

func New(deps Dependencies) *Handler {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &Handler{deps: deps}
}

// Login flow starts here
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state := oauth2.GenerateVerifier()
	verifier := oauth2.GenerateVerifier()

	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: state, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: !h.deps.InsecureCookies, MaxAge: 300})
	http.SetCookie(w, &http.Cookie{Name: verifierCookieName, Value: verifier, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: !h.deps.InsecureCookies, MaxAge: 300})

	// Redirect to IdP
	http.Redirect(w, r, h.deps.AuthCodeURL(state, verifier), http.StatusSeeOther)
}

// IdP callback returns here
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || r.URL.Query().Get("state") == "" || stateCookie.Value != r.URL.Query().Get("state") {
		h.logAuthFailure(r, "invalid_state", nil)
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	verifierCookie, err := r.Cookie(verifierCookieName)
	if err != nil || verifierCookie.Value == "" {
		h.logAuthFailure(r, "missing_verifier", nil)
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.logAuthFailure(r, "missing_code", nil)
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Echange code for tokens
	tokenSet, err := h.deps.ExchangeCode(r.Context(), code, verifierCookie.Value)
	if err != nil {
		h.logAuthFailure(r, "token_exchange_failed", err)
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	claims, rawIDToken, err := h.readClaims(r.Context(), tokenSet)
	if err != nil {
		h.logAuthFailure(r, "id_token_verification_failed", err)
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	csrf := oauth2.GenerateVerifier()

	if err := h.deps.Sessions.Create(w, session.Session{
		AccessToken:  tokenSet.AccessToken,
		RefreshToken: tokenSet.RefreshToken,
		IDToken:      rawIDToken,
		ExpiresAt:    tokenSet.Expiry,
		CSRFToken:    csrf,
		User:         claims,
	}); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: csrf, Path: "/", HttpOnly: false, SameSite: http.SameSiteLaxMode, Secure: !h.deps.InsecureCookies, MaxAge: int((24 * time.Hour).Seconds())})
	http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: !h.deps.InsecureCookies, Expires: time.Unix(0, 0), MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: verifierCookieName, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: !h.deps.InsecureCookies, Expires: time.Unix(0, 0), MaxAge: -1})

	h.deps.Logger.Info("security_event", "event", "auth_success", "sub", claims.Sub, "remote_ip", r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	current, ok, _ := h.deps.Sessions.Get(r)
	if err := h.deps.Sessions.Destroy(w, r); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", HttpOnly: false, SameSite: http.SameSiteLaxMode, Secure: !h.deps.InsecureCookies, Expires: time.Unix(0, 0), MaxAge: -1})

	if ok {
		h.deps.Logger.Info("security_event", "event", "logout", "sub", current.User.Sub, "remote_ip", r.RemoteAddr)
	}

	logoutURL := h.deps.EndSessionEndpoint
	if logoutURL == "" {
		logoutURL = "/login"
	} else if ok && current.IDToken != "" {
		logoutURL = appendIDTokenHint(logoutURL, current.IDToken)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"redirectTo": logoutURL})
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	current, ok, err := h.deps.Sessions.Get(r)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !ok {
		cookie, cookieErr := r.Cookie("session")
		cookieVal := ""
		if cookieErr == nil {
			n := min(8, len(cookie.Value))
			cookieVal = cookie.Value[:n] + "..."
		}
		h.deps.Logger.Info("auth_me_unauthorized", "has_cookie", cookieErr == nil, "cookie_prefix", cookieVal, "remote_ip", r.RemoteAddr)
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user := current.User
	if user.Picture != "" {
		user.Picture = "/auth/avatar"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(user)
}

func (h *Handler) Avatar(w http.ResponseWriter, r *http.Request) {
	current, ok, err := h.deps.Sessions.Get(r)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !ok {
		h.writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if current.User.Picture == "" {
		h.writeError(w, http.StatusNotFound, "not found")
		return
	}

	pictureURL, err := url.Parse(current.User.Picture)
	if err != nil || pictureURL.Scheme == "" || pictureURL.Host == "" || (pictureURL.Scheme != "http" && pictureURL.Scheme != "https") {
		h.writeError(w, http.StatusBadGateway, "bad gateway")
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, pictureURL.String(), nil)
	if err != nil {
		h.writeError(w, http.StatusBadGateway, "bad gateway")
		return
	}
	if current.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+current.AccessToken)
	}

	client := h.deps.AvatarHTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		h.writeError(w, http.StatusBadGateway, "bad gateway")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.writeError(w, http.StatusBadGateway, "bad gateway")
		return
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

func (h *Handler) readClaims(ctx context.Context, tokenSet *oauth2.Token) (session.UserClaims, string, error) {
	raw, _ := tokenSet.Extra("id_token").(string)
	if h.deps.VerifyIDToken != nil {
		claims, err := h.deps.VerifyIDToken(ctx, raw)
		return claims, raw, err
	}
	if raw == "" {
		return session.UserClaims{}, "", errors.New("missing id token")
	}

	return session.UserClaims{}, "", errors.New("id token verifier is not configured")
}

func (h *Handler) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *Handler) logAuthFailure(r *http.Request, reason string, err error) {
	args := []any{"event", "auth_failure", "error", reason, "remote_ip", r.RemoteAddr}
	if err != nil {
		args = append(args, "detail", err.Error())
	}
	h.deps.Logger.Info("security_event", args...)
}

func appendIDTokenHint(baseURL, idTokenHint string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	q.Set("id_token_hint", idTokenHint)
	u.RawQuery = q.Encode()
	return u.String()
}

func BuildEndSessionURL(baseURL, postLogoutRedirectURI, idTokenHint string) string {
	if baseURL == "" {
		return baseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
