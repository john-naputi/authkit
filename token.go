package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// generateToken returns a raw 32-byte token (base64url-encoded) and its sha256 hash.
func generateToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}

// hashToken converts a raw token string into a sha256 hash.
// Ensures the token decodes as base64url (defensive).
func hashToken(raw string) ([]byte, error) {
	if raw == "" {
		return nil, errors.New("empty")
	}
	// Validate shape: must be base64url decodable
	if _, err := base64.RawURLEncoding.DecodeString(raw); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:], nil
}
