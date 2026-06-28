package server

import (
	"log/slog"
	"net/http"

	"oidc-oauth2-idp/bff/internal/handler"
	"oidc-oauth2-idp/bff/internal/middleware"
)

func NewBFF(logger *slog.Logger, staticAssetsHandler http.Handler, auth *handler.Handler, apiProxy http.Handler, apiPathPrefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler.RegisterRoutes(mux, staticAssetsHandler, auth, apiProxy, apiPathPrefix)
	if apiProxy == nil {
		mux.Handle(apiPathPrefix+"/", http.NotFoundHandler())
	}

	stack := handler.BuildMiddlewareStack(auth, middleware.Recovery(nil))
	return middleware.RequestLogger(logger)(stack(mux))
}
