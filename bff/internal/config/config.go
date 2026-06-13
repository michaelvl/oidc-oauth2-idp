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
	OIDCScopes            []string
	BFFExternalURL        string
	SessionSecret         string
	SessionCookieName     string
	SessionStorageType    string
	RedisURL              string
	APIBaseURL            string
	StaticAssetsBaseURL   string
	ContentSecurityPolicy string
	InsecureCookies       bool
}

const DefaultContentSecurityPolicy = "default-src 'self'; script-src 'self'"

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
		OIDCScopes:            parseScopes(os.Getenv("OIDC_SCOPES")),
		BFFExternalURL:        strings.TrimSpace(os.Getenv("BFF_EXTERNAL_URL")),
		SessionSecret:         os.Getenv("SESSION_SECRET"),
		SessionCookieName:     defaultString("SESSION_COOKIE_NAME", "session"),
		SessionStorageType:    defaultString("SESSION_STORAGE_TYPE", "memory"),
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
	if c.BFFExternalURL == "" {
		errs = append(errs, errors.New("BFF_EXTERNAL_URL is required"))
	}
	if len(c.SessionSecret) < 32 {
		errs = append(errs, errors.New("SESSION_SECRET must be at least 32 bytes"))
	}
	switch c.SessionStorageType {
	case "memory", "cookie":
		// no additional requirements
	case "redis":
		if c.RedisURL == "" {
			errs = append(errs, errors.New("REDIS_URL is required when SESSION_STORAGE_TYPE=redis"))
		}
	default:
		errs = append(errs, fmt.Errorf("SESSION_STORAGE_TYPE must be one of: memory, redis, cookie (got %q)", c.SessionStorageType))
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

func parseScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"openid", "profile", "email", "offline_access"}
	}
	var scopes []string
	for _, s := range strings.Fields(raw) {
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
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
