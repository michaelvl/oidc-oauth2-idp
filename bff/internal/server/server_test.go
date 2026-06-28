package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthz_ReturnsOK(t *testing.T) {
	h := NewBFF(nil, staticHandler(t, "<html>ok</html>"), nil, nil, "/api")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestRoot_ReturnsIndex(t *testing.T) {
	h := NewBFF(nil, staticHandler(t, "<html>placeholder</html>"), nil, nil, "/api")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "placeholder") {
		t.Fatalf("expected index html body, got %q", rec.Body.String())
	}
}

func TestSPAFallback_NonAPIPathReturnsIndex(t *testing.T) {
	h := NewBFF(nil, staticHandler(t, "<html>fallback</html>"), nil, nil, "/api")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/projects", nil)

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "fallback") {
		t.Fatalf("expected index html body, got %q", rec.Body.String())
	}
}

func TestSPAFallback_APIPathIsNotIntercepted(t *testing.T) {
	h := NewBFF(nil, staticHandler(t, "<html>fallback</html>"), nil, nil, "/api")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

func staticHandler(t *testing.T, index string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(index))
	})
}
