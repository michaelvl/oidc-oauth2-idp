package server

import (
	"log/slog"
	"net/http"

	"oidc-oauth2-idp/bff/internal/bff"
	"oidc-oauth2-idp/bff/internal/middleware"
)

func NewBFF(logger *slog.Logger, staticAssetsHandler http.Handler, auth *bff.Handler, apiProxy http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	bff.RegisterRoutes(mux, staticAssetsHandler, auth, apiProxy)
	if apiProxy == nil {
		mux.Handle("/api/", http.NotFoundHandler())
	}

	stack := bff.BuildMiddlewareStack(auth, middleware.Recovery(nil))
	return middleware.RequestLogger(logger)(stack(mux))
}
