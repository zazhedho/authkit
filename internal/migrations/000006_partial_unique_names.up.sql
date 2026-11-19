-- Unique names and identifiers apply to live rows only, so a name or an email
-- can be reused after a soft delete.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_live ON users(email) WHERE deleted_at IS NULL;

DROP INDEX IF EXISTS idx_users_phone;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone)
    WHERE deleted_at IS NULL AND phone IS NOT NULL AND phone <> '';

ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS ux_roles_name_live ON roles(name) WHERE deleted_at IS NULL;

ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS ux_permissions_name_live ON permissions(name) WHERE deleted_at IS NULL;

ALTER TABLE menu_items DROP CONSTRAINT IF EXISTS menu_items_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS ux_menu_items_name_live ON menu_items(name) WHERE deleted_at IS NULL;
