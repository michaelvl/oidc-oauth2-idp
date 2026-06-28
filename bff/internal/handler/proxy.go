package handler

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"oidc-oauth2-idp/bff/internal/session"
)

type APIProxy struct {
	logger   *slog.Logger
	sessions *session.Manager
	proxy    *httputil.ReverseProxy
}

type StaticAssetsProxy struct {
	logger *slog.Logger
	proxy  *httputil.ReverseProxy
}

func NewAPIProxy(logger *slog.Logger, sessions *session.Manager, apiBaseURL, apiPathPrefix, upstreamPathPrefix string) (*APIProxy, error) {
	if strings.TrimSpace(apiBaseURL) == "" {
		return nil, errors.New("API_BASE_URL is required")
	}
	if sessions == nil {
		return nil, errors.New("sessions manager is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	target, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, err
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, errors.New("API_BASE_URL must include scheme and host")
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
		stripped := strings.TrimPrefix(req.URL.Path, apiPathPrefix)
		req.URL.Path = path.Join(upstreamPathPrefix, stripped)
		if req.URL.RawPath != "" {
			strippedRaw := strings.TrimPrefix(req.URL.RawPath, apiPathPrefix)
			req.URL.RawPath = path.Join(upstreamPathPrefix, strippedRaw)
		}
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Warn("api_proxy_upstream_error", "error", err.Error(), "path", r.URL.Path)
		writeJSONError(w, http.StatusBadGateway, "bad gateway")
	}

	return &APIProxy{logger: logger, sessions: sessions, proxy: rp}, nil
}

func (p *APIProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	forwarded := r.Clone(r.Context())
	forwarded.Header = r.Header.Clone()

	if !strings.HasPrefix(strings.TrimSpace(forwarded.Header.Get("Authorization")), "Bearer ") {
		// TokenForwarder middleware did not set a token (e.g. in tests or direct calls);
		// fall back to reading from the session.
		current, ok, err := p.sessions.Get(r)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if !ok || strings.TrimSpace(current.AccessToken) == "" {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		forwarded.Header.Set("Authorization", "Bearer "+current.AccessToken)
	}

	forwarded.Header.Set("X-Forwarded-Host", r.Host)
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		forwarded.Header.Set("X-Forwarded-For", host)
	}

	p.proxy.ServeHTTP(w, forwarded)
}

func NewStaticAssetsProxy(logger *slog.Logger, staticAssetsBaseURL string) (*StaticAssetsProxy, error) {
	if strings.TrimSpace(staticAssetsBaseURL) == "" {
		return nil, errors.New("STATIC_ASSETS_BASE_URL is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	target, err := url.Parse(staticAssetsBaseURL)
	if err != nil {
		return nil, err
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, errors.New("STATIC_ASSETS_BASE_URL must include scheme and host")
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Warn("static_assets_proxy_upstream_error", "error", err.Error(), "path", r.URL.Path)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return &StaticAssetsProxy{logger: logger, proxy: rp}, nil
}

func (p *StaticAssetsProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}
