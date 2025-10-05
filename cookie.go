package authkit

import (
	"net/http"
	"time"
)

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	secure := s.cfg.Env == "prod" || s.cfg.Env == "staging"
	c := &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    token,
		Path:     "/",
		Domain:   s.cfg.CookieDomain, // may be empty for host-only
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // default; can be made configurable later
		Secure:   secure,
	}
	http.SetCookie(w, c)
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	secure := s.cfg.Env == "prod" || s.cfg.Env == "staging"
	c := &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	}
	http.SetCookie(w, c)
}
