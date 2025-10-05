package authkit

import "net/http"

// mountRoutes binds all public endpoints onto the Server's mux.
func (s *Server) mountRoutes() {
	// --- Auth endpoints ---
	// /auth/start: protect by IP (coarse) + per-email (precise, enforced in handler)
	s.handle("POST", "/auth/start", s.handleAuthStart,
		s.limitIP(5, minute), s.limitEmail(3, 10*minute))

	// /auth/exchange: lighter per-IP cap (tokens are single-use anyway)
	s.handle("POST", "/auth/exchange", s.handleAuthExchange,
		s.limitIP(20, minute))

	// Browser callback + dev JSON callback
	s.handle("GET", "/auth/callback", s.handleAuthCallback)
	if s.cfg.Env != "prod" {
		s.handle("GET", "/auth/callback/json", s.handleAuthCallbackJSON)
	}

	// Logout (requires valid session)
	s.handle("POST", "/auth/logout", s.handleLogout, s.requireAuth())

	// --- Protected example ---
	// /me returns the current user info (requires auth)
	s.handle("GET", "/me", s.handleMe, s.requireAuth())
}

// handle attaches a method-guarded route with optional middlewares.
func (s *Server) handle(method, path string, h http.HandlerFunc, mws ...middleware) {
	var handler http.Handler = h
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}

	// Method guard around stdlib ServeMux.
	s.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

const (
	minute = 60 // seconds; used with limiter helpers
)
