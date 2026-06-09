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
	AccessTokenAUD        string
	APIBaseURL            string
	StaticAssetsBaseURL   string
	ContentSecurityPolicy string
	InsecureCookies       bool
}

const DefaultContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; connect-src 'self'"

type StaticConfig struct {
	StaticDir string
	Port      string
}

type APIConfig struct {
	DatabaseURL    string
	OIDCIssuerURL  string
	AccessTokenAUD string
	SeedData       bool
	SprintSingular string
	SprintPlural   string
	EpicSingular   string
	EpicPlural     string
	TaskSingular   string
	TaskPlural     string
}

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
		AccessTokenAUD:        strings.TrimSpace(os.Getenv("ACCESS_TOKEN_AUD")),
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

func LoadAPI() (APIConfig, error) {
	seedData, err := parseBoolDefault("SEED_DATA", false)
	if err != nil {
		return APIConfig{}, err
	}

	cfg := APIConfig{
		DatabaseURL:    strings.TrimSpace(os.Getenv("DATABASE_URL")),
		OIDCIssuerURL:  strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
		AccessTokenAUD: strings.TrimSpace(os.Getenv("ACCESS_TOKEN_AUD")),
		SeedData:       seedData,
		SprintSingular: defaultString("VITE_SPRINT_NAME_SINGULAR", "sprint"),
		SprintPlural:   defaultString("VITE_SPRINT_NAME_PLURAL", "sprints"),
		EpicSingular:   defaultString("VITE_EPIC_NAME_SINGULAR", "epic"),
		EpicPlural:     defaultString("VITE_EPIC_NAME_PLURAL", "epics"),
		TaskSingular:   defaultString("VITE_TASK_NAME_SINGULAR", "task"),
		TaskPlural:     defaultString("VITE_TASK_NAME_PLURAL", "tasks"),
	}

	if err := cfg.Validate(); err != nil {
		return APIConfig{}, err
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

func LoadStatic() (StaticConfig, error) {
	cfg := StaticConfig{
		StaticDir: strings.TrimSpace(os.Getenv("STATIC_DIR")),
		Port:      defaultString("PORT", "8082"),
	}
	if err := cfg.Validate(); err != nil {
		return StaticConfig{}, err
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

func (c StaticConfig) Validate() error {
	if strings.TrimSpace(c.Port) == "" {
		return errors.New("PORT cannot be empty")
	}

	return nil
}

func (c APIConfig) Validate() error {
	var errs []error

	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if c.OIDCIssuerURL == "" {
		errs = append(errs, errors.New("OIDC_ISSUER_URL is required"))
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
