-- Deleting the permissions also removes their role_permissions rows (ON DELETE CASCADE).
DELETE FROM permissions WHERE resource = 'configs';
DELETE FROM menu_items WHERE name = 'configs';

DROP TABLE IF EXISTS app_configs;
