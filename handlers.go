package authkit

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/john-naputi/authkit/httpapi"
)

// Utilities

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

func unauthorized(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
}

func tooMany(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_requests"})
}

func gone(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusGone, map[string]string{"error": msg})
}

func serverErr(w http.ResponseWriter) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_server_error"})
}

func clientIP(r *http.Request) *string {
	// NOTE: hosts can replace with a forwarded chain extractor upstream.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return &host
}

func userAgent(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}

func isSafeRedirectPath(p string) (string, bool) {
	// Only allow empty or paths that start with '/' and are not absolute URLs.
	if p == "" {
		return "", true
	}
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	// Disallow //host and any scheme-looking strings
	if strings.HasPrefix(p, "//") || strings.Contains(p, "://") {
		return "", false
	}
	return p, true
}

func (s *Server) buildMagicLink(rawToken string) (string, error) {
	u, err := url.Parse(s.cfg.AppOrigin)
	if err != nil {
		return "", err
	}
	u.Path = "/auth/callback"
	q := u.Query()
	q.Set("token", rawToken)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Handlers

// POST /auth/start
// Body: { "email": "...", "redirect_path": "/somewhere" }
func (s *Server) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	var req httpapi.StartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid_json")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if _, err := mail.ParseAddress(req.Email); err != nil || req.Email == "" {
		badRequest(w, "invalid_email")
		return
	}

	if s.rateLimit(w, r, keyEmail(req.Email), 3, 10*time.Minute) {
		return
	}

	redirect := ""
	if p, ok := isSafeRedirectPath(strings.TrimSpace(req.RedirectPath)); ok {
		redirect = p
	} else {
		badRequest(w, "invalid_redirect_path")
		return
	}

	// Upsert user
	ctx := r.Context()
	u, err := s.deps.Store.UpsertUserByEmail(ctx, req.Email)
	if err != nil {
		serverErr(w)
		return
	}

	// Generate token (raw) and hash
	raw, hash, err := generateToken()
	if err != nil {
		serverErr(w)
		return
	}

	// Persist login_link
	expiresAt := s.deps.Clock.Now().Add(s.cfg.LinkTTL)
	if err := s.deps.Store.CreateLoginLink(ctx, hash, u.ID, nullableStr(redirect), expiresAt, clientIP(r), userAgent(r)); err != nil {
		serverErr(w)
		return
	}

	// Build link
	link, err := s.buildMagicLink(raw)
	if err != nil {
		serverErr(w)
		return
	}

	// Send email (in non-prod we ignore failures and can optionally echo link back)
	var sendErr error
	if s.cfg.Env == "prod" {
		_, sendErr = s.deps.Mail.SendMagicLinkWithTTL(ctx, u.Email, link, s.cfg.LinkTTL)
		if sendErr != nil {
			// In prod, delivery must succeed
			serverErr(w)
			return
		}
	} else {
		_, _ = s.deps.Mail.SendMagicLinkWithTTL(ctx, u.Email, link, s.cfg.LinkTTL)
	}

	resp := httpapi.StartResponse{Ok: true, Message: "magic_link_sent", RedirectTo: redirect}

	// Dev nicety: echo link only when explicitly requested
	if s.cfg.Env != "prod" && r.Header.Get("X-Debug-Return-Link") == "1" {
		resp.MagicLink = link
	}

	writeJSON(w, http.StatusOK, resp)
}

// POST /auth/exchange
// Body: { "token": "raw32b64..." }
func (s *Server) handleAuthExchange(w http.ResponseWriter, r *http.Request) {
	var req httpapi.ExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid_json")
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	if len(req.Token) == 0 {
		badRequest(w, "invalid_token")
		return
	}
	hash, err := hashToken(req.Token)
	if err != nil {
		badRequest(w, "invalid_token")
		return
	}

	ctx := r.Context()
	ll, err := s.deps.Store.GetLoginLinkByHash(ctx, hash)
	if err != nil {
		gone(w, "invalid_or_consumed")
		return
	}
	now := s.deps.Clock.Now()
	if ll.ConsumedAt != nil || now.After(ll.ExpiresAt) {
		// Standardize both cases as 410
		gone(w, "link_expired_or_consumed")
		return
	}

	// Mark link consumed (single-use)
	usedUserID, storedRedirect, err := s.deps.Store.ConsumeLoginLink(ctx, ll.ID)
	if err != nil {
		serverErr(w)
		return
	}
	// Constant-time compare for paranoia, though IDs come from DB
	if subtle.ConstantTimeCompare([]byte(usedUserID), []byte(ll.UserID)) != 1 {
		serverErr(w)
		return
	}

	// Create session
	rawSess, sessHash, err := generateToken()
	if err != nil {
		serverErr(w)
		return
	}
	sessExp := now.Add(s.cfg.SessionTTL)
	if err := s.deps.Store.CreateSession(ctx, ll.UserID, sessHash, sessExp, clientIP(r), userAgent(r)); err != nil {
		serverErr(w)
		return
	}

	// Set cookie
	s.setSessionCookie(w, rawSess, sessExp)

	writeJSON(w, http.StatusOK, httpapi.ExchangeResponse{
		AccessToken: rawSess,
		ExpiresAt:   sessExp,
		Redirect:    coalesce(ll.RedirectPath, storedRedirect, &s.cfg.DefaultRedirect),
	})
}

// GET /auth/callback?token=...
// Browser flow: set cookie and redirect to stored path or DefaultRedirect.
// Ignores any r= in query in favor of the stored redirect_path captured on issuance.
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("token"))
	if raw == "" {
		badRequest(w, "missing_token")
		return
	}
	hash, err := hashToken(raw)
	if err != nil {
		badRequest(w, "invalid_token")
		return
	}

	ctx := r.Context()
	ll, err := s.deps.Store.GetLoginLinkByHash(ctx, hash)
	if err != nil || ll.ConsumedAt != nil || s.deps.Clock.Now().After(ll.ExpiresAt) {
		// Non-verbose on browser flow; you may customize to a branded HTML page.
		http.Error(w, "Link expired or already used.", http.StatusGone)
		return
	}

	_, storedRedirect, err := s.deps.Store.ConsumeLoginLink(ctx, ll.ID)
	if err != nil {
		serverErr(w)
		return
	}

	// Create session
	rawSess, sessHash, err := generateToken()
	if err != nil {
		serverErr(w)
		return
	}
	exp := s.deps.Clock.Now().Add(s.cfg.SessionTTL)
	if err := s.deps.Store.CreateSession(ctx, ll.UserID, sessHash, exp, clientIP(r), userAgent(r)); err != nil {
		serverErr(w)
		return
	}
	s.setSessionCookie(w, rawSess, exp)

	target := coalesce(ll.RedirectPath, storedRedirect, &s.cfg.DefaultRedirect)
	// Defensive: ensure target is a relative path
	if t, ok := isSafeRedirectPath(*target); ok {
		http.Redirect(w, r, t, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// GET /auth/callback/json (dev/test only)
func (s *Server) handleAuthCallbackJSON(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Env == "prod" {
		http.NotFound(w, r)
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("token"))
	if raw == "" {
		badRequest(w, "missing_token")
		return
	}
	// Re-use exchange logic by faking a POST body would be awkward; just inline.
	hash, err := hashToken(raw)
	if err != nil {
		badRequest(w, "invalid_token")
		return
	}
	ctx := r.Context()
	ll, err := s.deps.Store.GetLoginLinkByHash(ctx, hash)
	if err != nil || ll.ConsumedAt != nil || s.deps.Clock.Now().After(ll.ExpiresAt) {
		gone(w, "link_expired_or_consumed")
		return
	}
	_, storedRedirect, err := s.deps.Store.ConsumeLoginLink(ctx, ll.ID)
	if err != nil {
		serverErr(w)
		return
	}
	rawSess, sessHash, err := generateToken()
	if err != nil {
		serverErr(w)
		return
	}
	exp := s.deps.Clock.Now().Add(s.cfg.SessionTTL)
	if err := s.deps.Store.CreateSession(ctx, ll.UserID, sessHash, exp, clientIP(r), userAgent(r)); err != nil {
		serverErr(w)
		return
	}
	s.setSessionCookie(w, rawSess, exp)

	writeJSON(w, http.StatusOK, httpapi.ExchangeResponse{
		AccessToken: rawSess,
		ExpiresAt:   exp,
		Redirect:    coalesce(ll.RedirectPath, storedRedirect, &s.cfg.DefaultRedirect),
	})
}

// POST /auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Extract token (Bearer first, then cookie)
	raw := extractBearer(r.Header.Get("Authorization"))
	if raw == "" {
		if c, err := r.Cookie(s.cfg.CookieName); err == nil {
			raw = c.Value
		}
	}
	if raw == "" {
		unauthorized(w, "no_session")
		return
	}
	hash, err := hashToken(raw)
	if err != nil {
		unauthorized(w, "invalid_session")
		return
	}
	if err := s.deps.Store.RevokeSessionWithTokenHash(r.Context(), hash); err != nil {
		// For idempotence, do not leak existence
	}
	s.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

// GET /me (protected)
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userID := currentUserID(r.Context())
	if userID == "" {
		unauthorized(w, "unauthorized")
		return
	}
	u, err := s.deps.Store.GetUserByID(r.Context(), userID)
	if err != nil {
		unauthorized(w, "unauthorized")
		return
	}
	resp := httpapi.MeResponse{
		User: &httpapi.PublicUser{
			ID:        u.ID,
			Email:     u.Email,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// Helpers

func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// coalesce picks first non-nil pointer; always returns a non-nil pointer.
func coalesce[T any](ps ...*T) *T {
	for _, p := range ps {
		if p != nil {
			return p
		}
	}
	panic("coalesce: all nil")
}

func extractBearer(h string) string {
	if h == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// NOTE: demo utility not used directly but handy for tests/examples.
func (s *Server) debugCreateLoginLinkFor(ctx context.Context, email string, redirect string) (user User, link string, token string, err error) {
	user, err = s.deps.Store.UpsertUserByEmail(ctx, email)
	if err != nil {
		return
	}
	raw, hash, err := generateToken()
	if err != nil {
		return
	}
	err = s.deps.Store.CreateLoginLink(ctx, hash, user.ID, nullableStr(redirect), s.deps.Clock.Now().Add(15*time.Minute), nil, nil)
	if err != nil {
		return
	}
	link, err = s.buildMagicLink(raw)
	if err != nil {
		return
	}
	token = raw
	return
}

// Avoid unused import if uuid not used elsewhere; kept for illustrative patterns
var _ = uuid.Nil
var _ = errors.New
