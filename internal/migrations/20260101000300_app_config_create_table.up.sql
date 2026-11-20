CREATE TABLE IF NOT EXISTS app_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(150) NOT NULL UNIQUE,
    display_name VARCHAR(150) NOT NULL,
    category VARCHAR(100) NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_app_configs_category ON app_configs(category);
CREATE INDEX IF NOT EXISTS idx_app_configs_is_active ON app_configs(is_active);
CREATE INDEX IF NOT EXISTS idx_app_configs_deleted_at ON app_configs(deleted_at);

-- The name is the path without its leading slash.
INSERT INTO menu_items (id, name, display_name, path, icon, order_index, is_active)
SELECT gen_random_uuid(), ltrim(v.path, '/'), v.display_name, v.path, v.icon, v.order_index, TRUE
FROM (VALUES ('Configurations', '/configs', 'bi-sliders', 903)) AS v(display_name, path, icon, order_index)
ON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING;

INSERT INTO permissions (id, name, display_name, resource, action)
SELECT gen_random_uuid(), v.name, v.display_name, 'configs', v.action
FROM (VALUES
    ('list_configs', 'List Configurations', 'list'),
    ('view_configs', 'View Configuration Detail', 'view'),
    ('update_configs', 'Update Configurations', 'update')
) AS v(name, display_name, action)
ON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.resource = 'configs'
WHERE r.name IN ('admin', 'superadmin')
ON CONFLICT DO NOTHING;

INSERT INTO app_configs (id, config_key, display_name, category, value, description, is_active)
VALUES
    (
        gen_random_uuid(),
        'auth.public_registration_enabled',
        'Public Registration Enabled',
        'auth',
        'true',
        'Enable or disable public self-registration. When disabled, public register-related endpoints reject requests.',
        TRUE
    ),
    (
        gen_random_uuid(),
        'auth.register_otp_enabled',
        'Register OTP Enabled',
        'auth',
        'false',
        'Enable OTP verification for public user registration.',
        TRUE
    ),
    (
        gen_random_uuid(),
        'auth.password_reset_email_enabled',
        'Password Reset Email Enabled',
        'auth',
        'false',
        'Enable password reset tokens to be sent through the email sender service.',
        TRUE
    )
ON CONFLICT (config_key) DO NOTHING;
