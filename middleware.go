package authkit

import (
	"context"
	"net/http"
	"time"
)

// middleware is a lightweight wrapper type for composing handlers.
type middleware func(http.Handler) http.Handler

// Context key for attaching the authenticated user ID.
type ctxKey string

const userIDKey ctxKey = "authkit_user_id"

// withUserID returns a child context that carries the authenticated user ID.
func withUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// currentUserID extracts the authenticated user's ID from the context.
// Handlers like /me call this after requireAuth has run.
func currentUserID(ctx context.Context) string {
	if v, ok := ctx.Value(userIDKey).(string); ok {
		return v
	}
	return ""
}

// requireAuth validates Bearer/cookie tokens, checks the session against the store,
// touches last_used_at (throttled), and injects userID into the request context.
// If invalid/expired/revoked, it returns 401 JSON and stops the chain.
func (s *Server) requireAuth() middleware {
	return func(nextH http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1) Extract token (Bearer has precedence, then cookie)
			raw := extractBearer(r.Header.Get("Authorization"))
			if raw == "" {
				if c, err := r.Cookie(s.cfg.CookieName); err == nil {
					raw = c.Value
				}
			}
			if raw == "" {
				unauthorized(w, "missing_token")
				return
			}

			// 2) Hash + lookup session
			hash, err := hashToken(raw)
			if err != nil {
				unauthorized(w, "invalid_token")
				return
			}

			sess, err := s.deps.Store.GetSessionByTokenHash(r.Context(), hash)
			now := s.deps.Clock.Now()
			if err != nil || sess.RevokedAt != nil || now.After(sess.ExpiresAt) {
				unauthorized(w, "invalid_or_expired")
				return
			}

			// 3) Touch last_used_at at most once per minute (best-effort)
			if sess.LastUsedAt == nil || now.Sub(*sess.LastUsedAt) > time.Duration(s.lastTouchTTL)*time.Second {
				_ = s.deps.Store.TouchSessionLastUsed(r.Context(), sess.ID)
			}

			// 4) Continue with userID in context
			ctx := withUserID(r.Context(), sess.UserID)
			nextH.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
