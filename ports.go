package authkit

import (
	"context"
	"time"
)

// Store defines the persistence contract for AuthKit.
//
// Implementations of Store provide the data layer for AuthKit’s
// passwordless magic-link authentication flow. Each method corresponds
// to a well-defined lifecycle event in user authentication, from link
// issuance to session validation and revocation.
//
// The Store implementation must be safe for concurrent use and ensure
// uniqueness and expiry guarantees for tokens. Postgres is the
// reference implementation, but any backend (SQL or key-value) can
// implement this interface as long as it honors the semantics below.
type Store interface {

	// UpsertUserByEmail ensures that a user record exists for the given email.
	//
	// If a user with the given email already exists, it returns that user.
	// Otherwise, it creates a new user record and returns it.
	//
	// Typical behavior:
	//   - Normalize email (lowercase).
	//   - Ensure uniqueness on email.
	//   - Return a stable user ID for downstream references.
	//
	// This method is called when issuing a new magic link.
	UpsertUserByEmail(ctx context.Context, email string) (User, error)

	// CreateLoginLink inserts a new one-time magic-link token entry.
	//
	// The tokenHash is a SHA-256 hash of the magic link token (never the raw value).
	// redirectPath may be nil for default redirect behavior after login.
	// expiresAt defines the link’s lifetime.
	// Optional ip and ua fields may be used for audit logging or fraud detection.
	//
	// The token must be single-use and may not be reissued after expiration or consumption.
	CreateLoginLink(ctx context.Context, tokenHash []byte, userID string, redirectPath *string, expiresAt time.Time, ip *string, ua *string) error

	// GetLoginLinkByHash retrieves a pending login link record by its token hash.
	//
	// It returns the record’s ID, associated userID, redirectPath, expiration, and consumedAt timestamp.
	// If the token does not exist, has expired, or is invalid, an error should be returned.
	//
	// This method is used to validate inbound magic-link clicks before consumption.
	GetLoginLinkByHash(ctx context.Context, tokenHash []byte) (LoginLink, error)

	// ConsumeLoginLink marks a magic link as used and returns its userID and redirectPath.
	//
	// Implementations must ensure atomicity:
	//   - If already consumed or expired, return an error.
	//   - Otherwise, set consumedAt = now and return the linked user and redirect path.
	//
	// This method finalizes the magic-link authentication flow.
	ConsumeLoginLink(ctx context.Context, id string) (userID string, redirectPath *string, err error)

	// CreateSession creates a new session record for a successfully authenticated user.
	//
	// The tokenHash is a SHA-256 hash of the session token stored in the secure cookie.
	// expiresAt defines the session’s natural expiry.
	// Optional ip and ua fields may be used for telemetry or session management UI.
	//
	// Session tokens should be long-lived relative to login links and can be revoked.
	CreateSession(ctx context.Context, userID string, tokenHash []byte, expiresAt time.Time, ip *string, ua *string) error

	// GetSessionByTokenHash returns the session associated with the given token hash.
	//
	// It should return the sessionID, userID, expiry, revokedAt (if any), and lastUsedAt.
	// If no valid session is found, or if it is expired/revoked, return an error.
	//
	// This method powers middleware validation for protected routes like GET /me.
	GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (Session, error)

	// TouchSessionLastUsed updates the last-used timestamp for the given session.
	//
	// This may be called asynchronously or throttled (e.g., only once per 15 minutes)
	// to record user activity without excessive writes.
	TouchSessionLastUsed(ctx context.Context, sessionID string) error

	// RevokeSessionWithTokenHash invalidates a session identified by its token hash.
	//
	// Revoked sessions should be immediately considered invalid.
	// Typical use cases include explicit logout or admin termination.
	RevokeSessionWithTokenHash(ctx context.Context, tokenHash []byte) error

	// GetUserByID retrieves the user record for a given ID.
	//
	// Used by AuthKit when resolving /me and similar authenticated endpoints.
	GetUserByID(ctx context.Context, id string) (User, error)
}

// MailSender will be provided by the host (e.g., Postmark/SES/Sendgrid).
// For dev/test, a fake/no-op sender is fine.
type MailSender interface {
	// SendMagicLinkWithTTL returns a provider message ID if available (or empty string). Error must
	// reflect delivery failure; in non-prod environments, authkit will proceed
	// even if sending fails, so developers can copy magic links from responses
	// (behind an explicit header).
	SendMagicLinkWithTTL(ctx context.Context, to, link string, ttl time.Duration) (string, error)
}
