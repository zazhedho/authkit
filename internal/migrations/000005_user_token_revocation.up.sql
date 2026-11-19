-- tokens_valid_after revokes every token issued before it, per user.
ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMPTZ;

-- locked_until was never read or written by any code path.
DROP INDEX IF EXISTS idx_users_locked_until;
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
