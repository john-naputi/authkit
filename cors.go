package authkit

import (
	"net/http"
	"strings"
)

// Minimal CORS layer: allow only configured origins, credentials allowed for cookies.
type cors struct {
	allowed map[string]struct{}
}

func newCORS(cfg Config) *cors {
	allowed := map[string]struct{}{}
	if cfg.CORSOverrides != "" {
		for _, override := range strings.Split(cfg.CORSOverrides, ",") {
			override = strings.TrimSpace(override)
			if override != "" {
				allowed[override] = struct{}{}
			}
		}
	}

	if cfg.AppOrigin != "" {
		allowed[cfg.AppOrigin] = struct{}{}
	}

	return &cors{allowed: allowed}
}

// MaybeHandle processes CORS; returns true if the request was fully handled (e.g., OPTIONS).
func (c *cors) MaybeHandle(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	if _, ok := c.allowed[origin]; !ok {
		// Unknown origin. Do not add CORS headers. For preflight, reply 403.
		if r.Method == http.MethodOptions {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return true
		}

		return false
	}

	// Allowed origin
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		// Preflight
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		reqHeaders := r.Header.Get("Access-Control-Request-Headers")
		if reqHeaders == "" {
			reqHeaders = "Content-Type, Authorization"
		}

		w.Header().Set("Access-Controll-Allow-Headers", reqHeaders)
		w.WriteHeader(http.StatusNoContent)
		return true
	}

	return false
}
