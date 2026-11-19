CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'viewer',
    role_id UUID,
    email_verified_at TIMESTAMP,
    phone_verified_at TIMESTAMP,
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    last_login_user_agent TEXT,
    password_changed_at TIMESTAMP,
    -- Tokens issued before this instant are void; bumped on delete, role, password and email change.
    tokens_valid_after TIMESTAMPTZ,
    -- The "sub" of the linked Google account.
    google_subject VARCHAR(255),
    login_provider VARCHAR(50) DEFAULT 'local',
    avatar_url TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP
);

-- Unique values apply to live rows only, so an email or phone can be reused after a soft delete.
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_live ON users(email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone)
    WHERE deleted_at IS NULL AND phone IS NOT NULL AND phone <> '';
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_google_subject ON users(google_subject)
    WHERE deleted_at IS NULL AND google_subject IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_login_provider ON users(login_provider);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);

CREATE TABLE IF NOT EXISTS blacklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The hex sha256 of the revoked token, never the token itself.
    token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blacklist_token ON blacklist(token);
CREATE INDEX IF NOT EXISTS idx_blacklist_expires_at ON blacklist(expires_at);
