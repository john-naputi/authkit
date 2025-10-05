package authkit

import (
	"context"
	"time"
)

// User is the public shape the host must map to/from its DB layer.
// Keep all fields plain Go types to avoid pgx/sqlc/pgtype leakage.
type User struct {
	ID        string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store defines all persistence operations authkit needs.
// Implement this in the host app, typically as a thin adapter over sqlc/pgx.
type Store interface {
	UpsertUserByEmail(ctx context.Context, email string) (User, error)

	CreateLoginLink(ctx context.Context, tokenHash []byte, userID string, redirectPath *string, expiresAt time.Time, ip *string, ua *string) error
	GetLoginLinkByHash(ctx context.Context, tokenHash []byte) (id string, userID string, redirectPath *string, expiresAt time.Time, consumedAt *time.Time, err error)
	ConsumeLoginLink(ctx context.Context, id string) (userID string, redirectPath *string, err error)

	CreateSession(ctx context.Context, userID string, tokenHash []byte, expiresAt time.Time, ip *string, ua *string) error
	GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (sessionID string, userID string, expiresAt time.Time, revokedAt *time.Time, lastUsedAt *time.Time, err error)
	TouchSessionLastUsed(ctx context.Context, sessionID string) error
	RevokeSessionWithTokenHash(ctx context.Context, tokenHash []byte) error

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
