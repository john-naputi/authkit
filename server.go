package authkit

import (
	"net/http"
	"strings"
)

// Server is the public entry providing an http.Handler with all routes mounted.
type Server struct {
	cfg          Config
	deps         Deps
	mux          *http.ServeMux
	limiter      *rateLimiter
	cors         *cors
	lastTouchTTL int64 // seconds threshold for last_used_at touch (see middleware.go)
}

// New creates a new Server instance. It does not start listening.
func New(cfg Config, deps Deps) *Server {
	cfg.normalize()
	deps.normalize()

	s := &Server{
		cfg:          cfg,
		deps:         deps,
		mux:          http.NewServeMux(),
		limiter:      newRateLimiter(),
		cors:         newCORS(cfg),
		lastTouchTTL: 60, // touch last_used_at at most once per minute per session
	}

	s.mountRoutes()
	return s
}

// Handler returns the http.Handler with CORS and basic security headers applied.
func (s *Server) Handler() http.Handler {
	// Base handler with routes.
	h := s.mux

	// Wrap: CORS -> Security headers -> h
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS (also handles preflight OPTIONS)
		if handled := s.cors.MaybeHandle(w, r); handled {
			return
		}

		// Security headers for token endpoints (no-referrer + no-store).
		// Applied broadly and cheaply; browsers will ignore unknowns.
		if strings.HasPrefix(r.URL.Path, "/auth/") || r.URL.Path == "/me" {
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Cache-Control", "no-store")
		}

		h.ServeHTTP(w, r)
	})
}
