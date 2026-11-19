DROP INDEX IF EXISTS ux_menu_items_name_live;
DROP INDEX IF EXISTS ux_permissions_name_live;
DROP INDEX IF EXISTS ux_roles_name_live;
DROP INDEX IF EXISTS ux_users_email_live;

DROP INDEX IF EXISTS idx_users_phone;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone) WHERE phone IS NOT NULL AND phone <> '';

-- Restoring the table-wide constraints fails when a soft-deleted row shares a
-- name with a live one; clean those rows first.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_email_key' AND conrelid = 'users'::regclass) THEN
    ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'roles_name_key' AND conrelid = 'roles'::regclass) THEN
    ALTER TABLE roles ADD CONSTRAINT roles_name_key UNIQUE (name);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'permissions_name_key' AND conrelid = 'permissions'::regclass) THEN
    ALTER TABLE permissions ADD CONSTRAINT permissions_name_key UNIQUE (name);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'menu_items_name_key' AND conrelid = 'menu_items'::regclass) THEN
    ALTER TABLE menu_items ADD CONSTRAINT menu_items_name_key UNIQUE (name);
  END IF;
END$$;
