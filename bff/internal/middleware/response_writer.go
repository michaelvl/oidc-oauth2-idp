package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

type responseWriter struct {
	http.ResponseWriter
}

// Hijack is required so that httputil.ReverseProxy can upgrade connections to
// WebSocket (101 Switching Protocols). Without this, the proxy cannot take over
// the raw TCP connection and returns a 502 instead.
func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return hijacker.Hijack()
}

// Flush is required so that streaming responses (e.g. Server-Sent Events) are
// pushed to the client incrementally rather than buffered until the handler returns.
func (w *responseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
