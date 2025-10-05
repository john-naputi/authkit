BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
                                     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email CITEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

CREATE TABLE IF NOT EXISTS login_links (
                                           id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    redirect_path TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_ip INET NULL,
    created_ua TEXT NULL,
    CONSTRAINT login_links_consumed_once CHECK (consumed_at IS NULL OR consumed_at >= created_at)
    );
CREATE INDEX IF NOT EXISTS idx_login_links_user_id ON login_links(user_id);
CREATE INDEX IF NOT EXISTS idx_login_links_expires_at ON login_links(expires_at);
CREATE INDEX IF NOT EXISTS idx_login_links_consumed_at ON login_links(consumed_at);

CREATE TABLE IF NOT EXISTS sessions (
                                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    last_used_at TIMESTAMPTZ NULL,
    created_ip INET NULL,
    created_ua TEXT NULL,
    CONSTRAINT sessions_revoked_once CHECK (revoked_at IS NULL OR revoked_at >= created_at)
    );
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked_at ON sessions(revoked_at);
COMMIT;
