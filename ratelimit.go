package authkit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Simple in-memory sliding window counters.
// Good for single-instance setups (dev, small deployments).
// TODO: Replace with Redis or distributed store for multi-instance deployments.

type bucket struct {
	window time.Time
	count  int
}

type rateLimiter struct {
	mu   sync.Mutex
	data map[string]bucket
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{data: make(map[string]bucket)}
}

// allow checks if a request identified by key is within its rate limit.
// Returns true if allowed, false if limit exceeded.
func (rl *rateLimiter) allow(key string, limit int, per time.Duration, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.data[key]
	win := now.Truncate(per)
	if !ok || b.window.Before(win) {
		rl.data[key] = bucket{window: win, count: 1}
		return true
	}
	if b.count >= limit {
		return false
	}
	b.count++
	rl.data[key] = b
	return true
}

// middleware wrappers ---------------------------------------------------------

// limitIP enforces a per-IP rate limit on endpoints such as /auth/start or /auth/exchange.
func (s *Server) limitIP(limit, perSec int) middleware {
	per := time.Duration(perSec) * time.Second
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			k := keyIP(r)
			if s.rateLimit(w, r, k, limit, per) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// limitEmail is intentionally a no-op placeholder; email rate limits are applied
// after the JSON body is parsed inside the handler (since we need the email value).
func (s *Server) limitEmail(_, _ int) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimit checks and applies a limit for a given key. If limit exceeded, it
// writes a 429 JSON response and returns true (caller should stop).
func (s *Server) rateLimit(w http.ResponseWriter, _ *http.Request, key string, limit int, per time.Duration) bool {
	if key == "" {
		return false
	}
	if !s.limiter.allow(key, limit, per, s.deps.Clock.Now()) {
		tooMany(w)
		return true
	}
	return false
}

// key helpers -----------------------------------------------------------------

func keyIP(r *http.Request) string {
	// Normalize to just the host, not the ephemeral port.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return ""
	}
	return "ip:" + host
}

// keyEmail unchanged
func keyEmail(email string) string {
	e := strings.TrimSpace(strings.ToLower(email))
	if e == "" {
		return ""
	}
	return "email:" + e
}
