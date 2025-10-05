package httpapi

import "time"

// DTOs for HTTP JSON request/response payloads.

// StartRequest starts the magic-link flow.
type StartRequest struct {
	Email        string `json:"email"`
	RedirectPath string `json:"redirect_path"`
}

type StartResponse struct {
	Ok         bool   `json:"ok"`
	MagicLink  string `json:"magic_link,omitempty"` // dev only; gated by header
	Message    string `json:"message,omitempty"`
	RedirectTo string `json:"redirect_to,omitempty"`
}

type ExchangeRequest struct {
	Token string `json:"token"`
}

type ExchangeResponse struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Redirect    *string   `json:"redirect_to,omitempty"`
}

type PublicUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type MeResponse struct {
	User *PublicUser `json:"user"`
}

// Optional sample secure data response (not used by handlers; left for hosts)
type SecureDataResponse struct {
	Status string `json:"status"`
	UserID string `json:"user_id"`
}
