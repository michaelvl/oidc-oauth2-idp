package config

import "testing"

func seedRequiredBFFEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_ISSUER_URL", "http://idp:5001")
	t.Setenv("OIDC_CLIENT_ID", "client")
	t.Setenv("OIDC_CLIENT_SECRET", "secret")
	t.Setenv("OIDC_REDIRECT_URI", "http://localhost:8080/auth/callback")
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

func TestLoadAPI_RequiresOIDCIssuerURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://app:app@localhost:5432/app?sslmode=disable")
	t.Setenv("OIDC_ISSUER_URL", "")

	_, err := LoadAPI()
	if err == nil {
		t.Fatal("expected error when OIDC_ISSUER_URL is missing for API config")
	}
}

func TestLoadStatic_DefaultPort(t *testing.T) {
	t.Setenv("PORT", "")

	cfg, err := LoadStatic()
	if err != nil {
		t.Fatalf("expected static config to load, got: %v", err)
	}
	if cfg.Port != "8082" {
		t.Fatalf("expected default static port 8082, got %q", cfg.Port)
	}
}
