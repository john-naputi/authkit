package authkit

import (
	"net/netip"
	"time"
)

type User struct {
	ID        string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type LoginLink struct {
	ID           string
	UserID       string
	RedirectPath *string
	ExpiresAt    time.Time
	ConsumedAt   *time.Time
	CreatedIP    *netip.Addr // optional audit fields if you store them
	CreatedUA    *string
	CreatedAt    time.Time
}

type Session struct {
	ID         string
	UserID     string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	CreatedIP  *netip.Addr
	CreatedUA  *string
	CreatedAt  time.Time
}
