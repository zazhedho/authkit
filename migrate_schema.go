package authkit

import "sort"

// baselineSchema lists, per table, every column the baseline migrations
// (000001 to 000004) create. A database that already has the tables but no
// version table is only adopted when it has all of them. Keep it in step with
// the SQL; TestMigrateEmptyDatabase checks the two against a real database.
var baselineSchema = map[string][]string{
	"users": {
		"id", "name", "email", "phone", "password", "role", "role_id",
		"email_verified_at", "phone_verified_at", "last_login_at", "last_login_ip",
		"last_login_user_agent", "locked_until", "password_changed_at",
		"login_provider", "avatar_url", "metadata", "created_at", "updated_at", "deleted_at",
	},
	"blacklist": {"id", "token", "created_at", "expires_at"},
	"roles": {
		"id", "name", "display_name", "description", "is_system",
		"created_at", "updated_at", "deleted_at",
	},
	"permissions": {
		"id", "name", "display_name", "description", "resource", "action",
		"created_at", "updated_at", "deleted_at",
	},
	"menu_items": {
		"id", "name", "display_name", "path", "icon", "parent_id", "order_index",
		"is_active", "created_at", "updated_at", "deleted_at",
	},
	"role_permissions": {"id", "role_id", "permission_id", "created_at"},
	"role_menus":       {"id", "role_id", "menu_item_id", "created_at"},
	"audit_trails": {
		"id", "occurred_at", "actor_user_id", "actor_role", "action", "resource",
		"resource_id", "status", "message", "error_message", "request_id",
		"ip_address", "user_agent", "before_data", "after_data", "metadata", "created_at",
	},
	"app_configs": {
		"id", "config_key", "display_name", "category", "value", "description",
		"is_active", "created_at", "updated_at", "deleted_at",
	},
}

// missingFromSchema returns what expected requires and actual lacks, as "table"
// for a missing table and "table.column" for a missing column, sorted. Extra
// tables and columns in actual are ignored.
func missingFromSchema(expected, actual map[string][]string) []string {
	var missing []string
	for table, cols := range expected {
		have, ok := actual[table]
		if !ok {
			missing = append(missing, table)
			continue
		}
		set := make(map[string]struct{}, len(have))
		for _, c := range have {
			set[c] = struct{}{}
		}
		for _, c := range cols {
			if _, ok := set[c]; !ok {
				missing = append(missing, table+"."+c)
			}
		}
	}
	sort.Strings(missing)
	return missing
}
