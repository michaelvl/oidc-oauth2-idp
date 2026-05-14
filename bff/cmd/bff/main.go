package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"oidc-oauth2-idp/bff/internal/bff"
	"oidc-oauth2-idp/bff/internal/config"
	"oidc-oauth2-idp/bff/internal/server"
	"oidc-oauth2-idp/bff/internal/session"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("bff exited with error", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	bffCfg, serverCfg, err := requireConfig(logger)
	if err != nil {
		return err
	}

	store, err := session.NewStore(bffCfg.RedisURL)
	if err != nil {
		return fmt.Errorf("initialize session store: %w", err)
	}

	oidcDeps, err := bff.BuildOIDCDependenciesWithRetry(logger, bffCfg)
	if err != nil {
		return fmt.Errorf("initialize oidc: %w", err)
	}

	sessionManager := session.NewManager(store, bffCfg.SessionCookieName, bffCfg.SessionSecret, bffCfg.InsecureCookies)
	authHandler := bff.New(bff.Dependencies{
		Logger:             logger,
		Sessions:           sessionManager,
		AuthCodeURL:        oidcDeps.AuthCodeURL,
		ExchangeCode:       oidcDeps.ExchangeCode,
		VerifyIDToken:      oidcDeps.VerifyIDToken,
		EndSessionEndpoint: oidcDeps.EndSessionEndpoint,
		InsecureCookies:    bffCfg.InsecureCookies,
	})

	apiProxy, err := bff.NewAPIProxy(logger, sessionManager, bffCfg.APIBaseURL)
	if err != nil {
		return fmt.Errorf("initialize api proxy: %w", err)
	}

	staticAssetsProxy, err := bff.NewStaticAssetsProxy(logger, bffCfg.StaticAssetsBaseURL)
	if err != nil {
		return fmt.Errorf("initialize static assets proxy: %w", err)
	}

	handler := server.NewBFF(staticAssetsProxy, authHandler, apiProxy)
	addr := ":" + serverCfg.Port

	logger.Info("starting bff", "addr", addr)
	if err := http.ListenAndServe(addr, handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen and serve: %w", err)
	}

	return nil
}

func requireConfig(logger *slog.Logger) (config.BFFConfig, config.ServerConfig, error) {
	bffCfg, err := config.LoadBFF()
	if err != nil {
		logger.Error("bff configuration validation failed", "error", err.Error())
		return config.BFFConfig{}, config.ServerConfig{}, err
	}
	serverCfg, err := config.LoadServer()
	if err != nil {
		logger.Error("server configuration validation failed", "error", err.Error())
		return config.BFFConfig{}, config.ServerConfig{}, err
	}

	return bffCfg, serverCfg, nil
}
