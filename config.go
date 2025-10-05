package authkit

import "time"

// Config holds runtime behaviors that differ by environment or host app.
type Config struct {
	// AppOrigin is the canonical origin of the host (e.g., https://app.example.com).
	// Used to build absolute magic links and to drive default CORS.
	AppOrigin string

	// Env: "prod" | "staging" | "dev" | "test"
	Env string

	// CookieName is the session cookie name (e.g., "ak_session").
	CookieName string

	// CookieDomain optional; leave empty to use host-only cookie.
	CookieDomain string

	// DefaultRedirect used by /auth/callback when no redirect_path was stored.
	DefaultRedirect string

	// SessionTTL determines how long a session token remains valid.
	SessionTTL time.Duration

	// LinkTTL determines how long a one-time login link remains valid.
	LinkTTL time.Duration

	// Optional: Comma-separated overrides for allowed CORS origins. If empty,
	// AppOrigin is used. (See cors.go)
	CORSOverrides string
}

// Deps are side-effecting dependencies host apps must provide/compose.
type Deps struct {
	Store Store
	Mail  MailSender
	Clock Clock
}

// Clock is an injectable time source to enable deterministic tests.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

// normalize fills defaults and validates a minimal viable config.
func (c *Config) normalize() {
	if c.CookieName == "" {
		c.CookieName = "ak_session"
	}
	if c.DefaultRedirect == "" {
		c.DefaultRedirect = "/"
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 30 * 24 * time.Hour
	}
	if c.LinkTTL == 0 {
		c.LinkTTL = 15 * time.Minute
	}
}

func (d *Deps) normalize() {
	if d.Clock == nil {
		d.Clock = realClock{}
	}
}
