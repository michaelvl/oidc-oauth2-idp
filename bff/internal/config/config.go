package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type BFFConfig struct {
	OIDCIssuerURL         string
	OIDCClientID          string
	OIDCClientSecret      string
	OIDCRedirectURI       string
	SessionSecret         string
	SessionCookieName     string
	RedisURL              string
	APIBaseURL            string
	StaticAssetsBaseURL   string
	ContentSecurityPolicy string
	InsecureCookies       bool
}

const DefaultContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; connect-src 'self'"

type ServerConfig struct {
	Port string
}

func LoadBFF() (BFFConfig, error) {
	insecureCookies, err := parseBoolDefault("INSECURE_COOKIES", false)
	if err != nil {
		return BFFConfig{}, err
	}

	cfg := BFFConfig{
		OIDCIssuerURL:         strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
		OIDCClientID:          strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		OIDCClientSecret:      strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET")),
		OIDCRedirectURI:       strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URI")),
		SessionSecret:         os.Getenv("SESSION_SECRET"),
		SessionCookieName:     defaultString("SESSION_COOKIE_NAME", "session"),
		RedisURL:              strings.TrimSpace(os.Getenv("REDIS_URL")),
		APIBaseURL:            strings.TrimSpace(os.Getenv("API_BASE_URL")),
		StaticAssetsBaseURL:   strings.TrimSpace(os.Getenv("STATIC_ASSETS_BASE_URL")),
		ContentSecurityPolicy: defaultString("CONTENT_SECURITY_POLICY", DefaultContentSecurityPolicy),
		InsecureCookies:       insecureCookies,
	}

	if err := cfg.Validate(); err != nil {
		return BFFConfig{}, err
	}

	return cfg, nil
}

func LoadServer() (ServerConfig, error) {
	cfg := ServerConfig{Port: defaultString("PORT", "8080")}
	if err := cfg.Validate(); err != nil {
		return ServerConfig{}, err
	}
	return cfg, nil
}

func (c BFFConfig) Validate() error {
	var errs []error

	if c.OIDCIssuerURL == "" {
		errs = append(errs, errors.New("OIDC_ISSUER_URL is required"))
	}
	if c.OIDCClientID == "" {
		errs = append(errs, errors.New("OIDC_CLIENT_ID is required"))
	}
	if c.OIDCClientSecret == "" {
		errs = append(errs, errors.New("OIDC_CLIENT_SECRET is required"))
	}
	if c.OIDCRedirectURI == "" {
		errs = append(errs, errors.New("OIDC_REDIRECT_URI is required"))
	}
	if len(c.SessionSecret) < 32 {
		errs = append(errs, errors.New("SESSION_SECRET must be at least 32 bytes"))
	}
	if c.APIBaseURL == "" {
		errs = append(errs, errors.New("API_BASE_URL is required"))
	}
	if c.StaticAssetsBaseURL == "" {
		errs = append(errs, errors.New("STATIC_ASSETS_BASE_URL is required"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (c ServerConfig) Validate() error {
	if strings.TrimSpace(c.Port) == "" {
		return errors.New("PORT cannot be empty")
	}

	return nil
}

func defaultString(key, value string) string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return value
	}
	return raw
}

func parseBoolDefault(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}

	return v, nil
}
