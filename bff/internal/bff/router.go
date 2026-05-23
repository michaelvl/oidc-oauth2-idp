package bff

import (
	"net/http"
)

func RegisterRoutes(mux *http.ServeMux, staticAssetsHandler http.Handler, auth *Handler, apiProxy http.Handler) {
	if mux == nil {
		return
	}

	if auth != nil {
		mux.HandleFunc("GET /auth/login", auth.Login)
		mux.HandleFunc("GET /auth/callback", auth.Callback)
		mux.HandleFunc("POST /auth/logout", auth.Logout)
		mux.HandleFunc("GET /auth/me", auth.Me)
		mux.HandleFunc("GET /auth/avatar", auth.Avatar)
	}

	if apiProxy != nil {
		mux.Handle("/api/", apiProxy)
		mux.Handle("/api", apiProxy)
	}

	if staticAssetsHandler != nil {
		mux.Handle("/", staticAssetsHandler)
	}
}

func BuildMiddlewareStack(auth *Handler, recovery func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		h := next
		if recovery != nil {
			h = recovery(h)
		}
		if auth != nil {
			h = auth.SecurityHeaders(auth.AuthGuard(auth.CSRFMiddleware(h)))
		}
		return h
	}
}
