package bff

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"oidc-oauth2-idp/bff/internal/config"
	"oidc-oauth2-idp/bff/internal/session"
)

type OIDCDependencies struct {
	AuthCodeURL        func(state, codeVerifier string) string
	ExchangeCode       func(ctx context.Context, code, verifier string) (*oauth2.Token, error)
	VerifyIDToken      func(ctx context.Context, rawIDToken string) (session.UserClaims, error)
	RefreshTokens      func(ctx context.Context, refreshToken string) (*oauth2.Token, error)
	EndSessionEndpoint string
}

func BuildOIDCDependenciesWithRetry(logger *slog.Logger, cfg config.BFFConfig) (OIDCDependencies, error) {
	const (
		maxAttempts = 30
		retryDelay  = 2 * time.Second
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		deps, err := BuildOIDCDependencies(cfg)
		if err == nil {
			if attempt > 1 && logger != nil {
				logger.Info("oidc provider became available", "attempt", attempt)
			}
			return deps, nil
		}

		lastErr = err
		if attempt < maxAttempts {
			if logger != nil {
				logger.Warn("oidc provider not ready, retrying", "attempt", attempt, "max_attempts", maxAttempts, "retry_delay", retryDelay.String(), "error", err.Error())
			}
			time.Sleep(retryDelay)
		}
	}

	return OIDCDependencies{}, fmt.Errorf("oidc provider unavailable after %d attempts: %w", maxAttempts, lastErr)
}

func BuildOIDCDependencies(cfg config.BFFConfig) (OIDCDependencies, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuerURL)
	if err != nil {
		return OIDCDependencies{}, fmt.Errorf("create oidc provider: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.BFFExternalURL + "/auth/callback",
		Scopes:       cfg.OIDCScopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID})

	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil {
		metadata.EndSessionEndpoint = ""
	}

	client := OAuthClient{Config: oauthConfig}
	logoutRedirect := BuildEndSessionURL(metadata.EndSessionEndpoint, cfg.BFFExternalURL+"/login", "")

	return OIDCDependencies{
		AuthCodeURL:   client.AuthCodeURL,
		ExchangeCode:  client.ExchangeCode,
		RefreshTokens: client.RefreshTokens,
		VerifyIDToken: func(ctx context.Context, rawIDToken string) (session.UserClaims, error) {
			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				return session.UserClaims{}, err
			}

			var claims struct {
				Sub     string `json:"sub"`
				Name    string `json:"name"`
				Email   string `json:"email"`
				Picture string `json:"picture"`
			}
			if err := idToken.Claims(&claims); err != nil {
				return session.UserClaims{}, err
			}

			return session.UserClaims{Sub: claims.Sub, Name: claims.Name, Email: claims.Email, Picture: claims.Picture}, nil
		},
		EndSessionEndpoint: logoutRedirect,
	}, nil
}

