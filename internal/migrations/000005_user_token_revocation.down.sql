ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until);
ALTER TABLE users DROP COLUMN IF EXISTS tokens_valid_after;
