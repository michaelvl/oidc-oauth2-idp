package config

import "testing"

func seedRequiredBFFEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_ISSUER_URL", "http://idp:5001")
	t.Setenv("OIDC_CLIENT_ID", "client")
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	t.Setenv("BFF_EXTERNAL_URL", "http://localhost:8080")
	t.Setenv("SESSION_SECRET", "01234567890123456789012345678901")
	t.Setenv("API_BASE_URL", "http://localhost:8081")
	t.Setenv("STATIC_ASSETS_BASE_URL", "http://localhost:8082")
}

func TestLoadBFF_RequiresAPIAndStaticAssetsBaseURL(t *testing.T) {
	seedRequiredBFFEnv(t)
	t.Setenv("API_BASE_URL", "")

	_, err := LoadBFF()
	if err == nil {
		t.Fatal("expected error when API_BASE_URL is missing")
	}

	seedRequiredBFFEnv(t)
	t.Setenv("STATIC_ASSETS_BASE_URL", "")
	_, err = LoadBFF()
	if err == nil {
		t.Fatal("expected error when STATIC_ASSETS_BASE_URL is missing")
	}
}

func TestLoadBFF_DefaultContentSecurityPolicy(t *testing.T) {
	seedRequiredBFFEnv(t)

	cfg, err := LoadBFF()
	if err != nil {
		t.Fatalf("expected bff config to load, got: %v", err)
	}
	if cfg.ContentSecurityPolicy != DefaultContentSecurityPolicy {
		t.Fatalf("expected default CSP %q, got %q", DefaultContentSecurityPolicy, cfg.ContentSecurityPolicy)
	}
}

func TestLoadBFF_ContentSecurityPolicyOverride(t *testing.T) {
	seedRequiredBFFEnv(t)
	t.Setenv("CONTENT_SECURITY_POLICY", "default-src 'none'; script-src 'self'")

	cfg, err := LoadBFF()
	if err != nil {
		t.Fatalf("expected bff config to load, got: %v", err)
	}
	if cfg.ContentSecurityPolicy != "default-src 'none'; script-src 'self'" {
		t.Fatalf("expected CSP override to be applied, got %q", cfg.ContentSecurityPolicy)
	}
}

func TestLoadBFF_DefaultSessionStorageType(t *testing.T) {
	seedRequiredBFFEnv(t)

	cfg, err := LoadBFF()
	if err != nil {
		t.Fatalf("expected bff config to load, got: %v", err)
	}
	if cfg.SessionStorageType != "memory" {
		t.Fatalf("expected default session storage type %q, got %q", "memory", cfg.SessionStorageType)
	}
}

func TestLoadBFF_SessionStorageTypeRedis_RequiresRedisURL(t *testing.T) {
	seedRequiredBFFEnv(t)
	t.Setenv("SESSION_STORAGE_TYPE", "redis")
	// REDIS_URL not set

	_, err := LoadBFF()
	if err == nil {
		t.Fatal("expected error when SESSION_STORAGE_TYPE=redis but REDIS_URL is missing")
	}
}

func TestLoadBFF_SessionStorageTypeRedis_Valid(t *testing.T) {
	seedRequiredBFFEnv(t)
	t.Setenv("SESSION_STORAGE_TYPE", "redis")
	t.Setenv("REDIS_URL", "redis://127.0.0.1:6379")

	cfg, err := LoadBFF()
	if err != nil {
		t.Fatalf("expected bff config to load, got: %v", err)
	}
	if cfg.SessionStorageType != "redis" {
		t.Fatalf("expected session storage type %q, got %q", "redis", cfg.SessionStorageType)
	}
}

func TestLoadBFF_SessionStorageTypeCookie_Valid(t *testing.T) {
	seedRequiredBFFEnv(t)
	t.Setenv("SESSION_STORAGE_TYPE", "cookie")

	cfg, err := LoadBFF()
	if err != nil {
		t.Fatalf("expected bff config to load, got: %v", err)
	}
	if cfg.SessionStorageType != "cookie" {
		t.Fatalf("expected session storage type %q, got %q", "cookie", cfg.SessionStorageType)
	}
}

func TestLoadBFF_SessionStorageTypeUnknown_Fails(t *testing.T) {
	seedRequiredBFFEnv(t)
	t.Setenv("SESSION_STORAGE_TYPE", "invalid")

	_, err := LoadBFF()
	if err == nil {
		t.Fatal("expected error for unknown SESSION_STORAGE_TYPE")
	}
}

func TestLoadBFF_APIUpstreamPathPrefix_DefaultsToAPIPathPrefix(t *testing.T) {
	seedRequiredBFFEnv(t)

	cfg, err := LoadBFF()
	if err != nil {
		t.Fatalf("expected bff config to load, got: %v", err)
	}
	if cfg.APIUpstreamPathPrefix != cfg.APIPathPrefix {
		t.Fatalf("expected APIUpstreamPathPrefix to default to APIPathPrefix %q, got %q", cfg.APIPathPrefix, cfg.APIUpstreamPathPrefix)
	}
}

func TestLoadBFF_APIUpstreamPathPrefix_Override(t *testing.T) {
	seedRequiredBFFEnv(t)
	t.Setenv("API_PATH_PREFIX", "/api")
	t.Setenv("API_UPSTREAM_PATH_PREFIX", "/v2")

	cfg, err := LoadBFF()
	if err != nil {
		t.Fatalf("expected bff config to load, got: %v", err)
	}
	if cfg.APIPathPrefix != "/api" {
		t.Fatalf("expected APIPathPrefix /api, got %q", cfg.APIPathPrefix)
	}
	if cfg.APIUpstreamPathPrefix != "/v2" {
		t.Fatalf("expected APIUpstreamPathPrefix /v2, got %q", cfg.APIUpstreamPathPrefix)
	}
}
