-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

-- Create permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

-- Create menu_items table
CREATE TABLE IF NOT EXISTS menu_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    path VARCHAR(255) NOT NULL,
    icon VARCHAR(50),
    parent_id UUID,
    order_index INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    FOREIGN KEY (parent_id) REFERENCES menu_items(id) ON DELETE SET NULL
);

-- Create role_permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE(role_id, permission_id)
);

-- Create role_menus junction table
CREATE TABLE IF NOT EXISTS role_menus (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL,
    menu_item_id UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (menu_item_id) REFERENCES menu_items(id) ON DELETE CASCADE,
    UNIQUE(role_id, menu_item_id)
);

-- Names are unique among live rows only, so a name can be reused after a soft delete.
CREATE UNIQUE INDEX IF NOT EXISTS ux_roles_name_live ON roles(name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_permissions_name_live ON permissions(name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_menu_items_name_live ON menu_items(name) WHERE deleted_at IS NULL;

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_permissions_resource_action ON permissions(resource, action);
CREATE INDEX IF NOT EXISTS idx_menu_items_parent_id ON menu_items(parent_id);
CREATE INDEX IF NOT EXISTS idx_menu_items_order ON menu_items(order_index);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_role_menus_role_id ON role_menus(role_id);
CREATE INDEX IF NOT EXISTS idx_role_menus_menu_item_id ON role_menus(menu_item_id);

-- Add foreign key to users table
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'fk_users_role'
      AND conrelid = 'users'::regclass
  ) THEN
    ALTER TABLE users
    ADD CONSTRAINT fk_users_role
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL;
  END IF;
END$$;
CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);

-- Insert system roles
INSERT INTO roles (id, name, display_name, description, is_system) VALUES
    (gen_random_uuid(), 'superadmin', 'Super Administrator', 'Full system access with highest privileges', TRUE),
    (gen_random_uuid(), 'admin', 'Administrator', 'Full system access', TRUE),
    (gen_random_uuid(), 'staff', 'Staff', 'Staff access with limited permissions', TRUE),
    (gen_random_uuid(), 'viewer', 'Viewer', 'Read-only access', TRUE)
ON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING;

-- Insert menu items. The name is the path without its leading slash.
INSERT INTO menu_items (id, name, display_name, path, icon, order_index)
SELECT gen_random_uuid(), ltrim(v.path, '/'), v.display_name, v.path, v.icon, v.order_index
FROM (VALUES
    ('Dashboard', '/dashboard', 'bi-speedometer2', 1),
    ('Profile', '/profile', 'bi-person-circle', 2),
    ('Users', '/users', 'bi-people', 900),
    ('Roles', '/roles', 'bi-shield-lock', 901),
    ('Menus', '/menus', 'bi-list-ul', 902),
    ('Audit Trails', '/audits', 'bi-journal-text', 904)
) AS v(display_name, path, icon, order_index)
ON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING;

-- Insert permissions. The k row holds each resource and action name once.
WITH k AS (
    SELECT 'dashboard' AS dashboard, 'users' AS users, 'roles' AS roles, 'menus' AS menus,
           'permissions' AS permissions, 'audits' AS audits, 'profile' AS profile,
           'create' AS create_, 'update' AS update_, 'delete' AS delete_
)
INSERT INTO permissions (id, name, display_name, resource, action)
SELECT gen_random_uuid(), v.name, v.display_name, v.resource, v.action
FROM k
CROSS JOIN LATERAL (VALUES
    -- Dashboard permissions
    ('view_dashboard', 'View Dashboard', k.dashboard, 'view'),

    -- User permissions
    ('list_users', 'List Users', k.users, 'list'),
    ('view_users', 'View User Detail', k.users, 'view'),
    ('create_users', 'Create Users', k.users, k.create_),
    ('impersonate_users', 'Impersonate Users', k.users, 'impersonate'),
    ('update_users', 'Update Users', k.users, k.update_),
    ('assign_role_users', 'Assign User Roles', k.users, 'assign_role'),
    ('update_password_users', 'Update Password Users', k.users, 'update_password'),
    ('delete_users', 'Delete Users', k.users, k.delete_),

    -- Role permissions
    ('list_roles', 'List Roles', k.roles, 'list'),
    ('view_roles', 'View Role Detail', k.roles, 'view'),
    ('create_roles', 'Create Roles', k.roles, k.create_),
    ('update_roles', 'Update Roles', k.roles, k.update_),
    ('delete_roles', 'Delete Roles', k.roles, k.delete_),
    ('manage_system_roles', 'Manage System Roles', k.roles, 'manage_system'),
    ('assign_permissions', 'Assign Permissions', k.roles, 'assign_permissions'),

    -- Menu permissions
    ('list_menus', 'List Menus', k.menus, 'list'),
    ('view_menu', 'View Menu Detail', k.menus, 'view'),
    ('update_menu', 'Update Menu', k.menus, k.update_),

    -- Permission management permissions
    ('list_permissions', 'List Permissions', k.permissions, 'list'),
    ('view_permissions', 'View Permission Detail', k.permissions, 'view'),
    ('create_permissions', 'Create Permissions', k.permissions, k.create_),
    ('update_permissions', 'Update Permissions', k.permissions, k.update_),
    ('delete_permissions', 'Delete Permissions', k.permissions, k.delete_),

    -- Audit permissions
    ('list_audits', 'List Audit Trails', k.audits, 'list'),
    ('view_audits', 'View Audit Trail Detail', k.audits, 'view'),

    -- Profile permissions
    ('view_profile', 'View Profile', k.profile, 'view'),
    ('update_profile', 'Update Profile', k.profile, k.update_),
    ('update_password_profile', 'Update Password Profile', k.profile, 'update_password'),
    ('delete_profile', 'Delete Profile', k.profile, k.delete_)
) AS v(name, display_name, resource, action)
ON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING;

-- admin and superadmin get every permission. staff gets read and write, and viewer
-- gets read only, on the dashboard, menu and profile resources.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p
    ON r.name IN ('admin', 'superadmin')
    OR (p.resource IN ('dashboard', 'menus', 'profile') AND (
        (r.name = 'staff' AND p.action IN ('list', 'view', 'create', 'update'))
        OR (r.name = 'viewer' AND p.action IN ('list', 'view'))
    ))
ON CONFLICT DO NOTHING;
