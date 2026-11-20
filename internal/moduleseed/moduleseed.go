package moduleseed

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

var defaultActions = []string{"list", "view", "create", "update", "delete"}

// Definition describes one module to seed: its menu entry, permissions and role grants.
type Definition struct {
	Name        string
	DisplayName string
	Path        string
	Icon        string
	OrderIndex  int
	ParentName  string
	Resource    string
	Actions     []string
	GrantRoles  []string
}

func (d Definition) Normalize() Definition {
	d.Name = serviceshared.NormalizeKey(d.Name)
	d.DisplayName = strings.TrimSpace(d.DisplayName)
	d.Path = strings.TrimSpace(d.Path)
	d.Icon = strings.TrimSpace(d.Icon)
	d.ParentName = serviceshared.NormalizeKey(d.ParentName)
	d.Resource = serviceshared.NormalizeKey(d.Resource)

	if d.Resource == "" {
		d.Resource = d.Name
	}
	if len(d.Actions) == 0 {
		d.Actions = append([]string{}, defaultActions...)
	}

	normalizedActions := make([]string, 0, len(d.Actions))
	for _, action := range d.Actions {
		action = serviceshared.NormalizeKey(action)
		if action == "" || slices.Contains(normalizedActions, action) {
			continue
		}
		normalizedActions = append(normalizedActions, action)
	}
	d.Actions = normalizedActions

	normalizedRoles := make([]string, 0, len(d.GrantRoles))
	for _, role := range d.GrantRoles {
		role = serviceshared.NormalizeKey(role)
		if role == "" || slices.Contains(normalizedRoles, role) {
			continue
		}
		normalizedRoles = append(normalizedRoles, role)
	}
	d.GrantRoles = normalizedRoles

	return d
}

func (d Definition) Validate() error {
	if d.Name == "" {
		return errors.New("name is required")
	}
	if d.DisplayName == "" {
		return errors.New("display_name is required")
	}
	if d.Path == "" {
		return errors.New("path is required")
	}
	if d.Resource == "" {
		return errors.New("resource is required")
	}
	if len(d.Actions) == 0 {
		return errors.New("at least one action is required")
	}

	// Values end up inside a DO block and quoted literals, so they are held to a
	// plain alphabet. Module, resource, parent and role names may use "-"
	// (kebab-case); actions are part of permission names and may not.
	for field, value := range map[string]string{"name": d.Name, "resource": d.Resource, "parent_name": d.ParentName} {
		if value != "" && !reName.MatchString(value) {
			return fmt.Errorf("%s %q must match %s", field, value, reName)
		}
	}
	for _, role := range d.GrantRoles {
		if !reName.MatchString(role) {
			return fmt.Errorf("grant role %q must match %s", role, reName)
		}
	}
	for _, action := range d.Actions {
		if !reAction.MatchString(action) {
			return fmt.Errorf("action %q must match %s", action, reAction)
		}
	}

	return nil
}

var (
	reName   = regexp.MustCompile(`^[a-z0-9_-]+$`)
	reAction = regexp.MustCompile(`^[a-z0-9_]+$`)
)

func RenderSQL(input Definition) (string, error) {
	def := input.Normalize()
	if err := def.Validate(); err != nil {
		return "", err
	}

	var sections []string
	sections = append(sections, renderMenuInsert(def))
	sections = append(sections, renderCollisionGuard(def))
	sections = append(sections, renderPermissionInsert(def))
	if len(def.GrantRoles) > 0 {
		sections = append(sections, renderRolePermissionInsert(def))
	}

	return strings.Join(sections, "\n\n"), nil
}

func renderMenuInsert(def Definition) string {
	columns := []string{"id", "name", "display_name", "path", "icon", "order_index", "is_active"}
	values := []string{
		"gen_random_uuid()",
		quote(def.Name),
		quote(def.DisplayName),
		quote(def.Path),
		quote(def.Icon),
		fmt.Sprintf("%d", def.OrderIndex),
		"TRUE",
	}

	if def.ParentName != "" {
		columns = []string{"id", "name", "display_name", "path", "icon", "parent_id", "order_index", "is_active"}
		values = []string{
			"gen_random_uuid()",
			quote(def.Name),
			quote(def.DisplayName),
			quote(def.Path),
			quote(def.Icon),
			fmt.Sprintf("(SELECT id FROM menu_items WHERE name = %s AND deleted_at IS NULL LIMIT 1)", quote(def.ParentName)),
			fmt.Sprintf("%d", def.OrderIndex),
			"TRUE",
		}
	}

	return fmt.Sprintf(
		"INSERT INTO menu_items (%s)\nVALUES\n    (%s)\nON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING;",
		strings.Join(columns, ", "),
		strings.Join(values, ", "),
	)
}

// renderCollisionGuard stops the migration when a generated permission name
// exists for another resource or action; ON CONFLICT DO NOTHING would skip it
// and the role grants would hand out the wrong permission.
func renderCollisionGuard(def Definition) string {
	expected := make([]string, 0, len(def.Actions))
	for _, action := range def.Actions {
		expected = append(expected, fmt.Sprintf("(%s, %s, %s)", quote(permissionName(action, def.Name)), quote(def.Resource), quote(action)))
	}
	return fmt.Sprintf(`DO $authkit$
BEGIN
  IF EXISTS (
    SELECT 1 FROM permissions p
    WHERE p.deleted_at IS NULL
      AND p.name IN (%s)
      AND (p.name, p.resource, p.action) NOT IN (VALUES %s)
  ) THEN
    RAISE EXCEPTION 'module-seed: a permission named like one of this module''s already exists for another resource or action';
  END IF;
END$authkit$;`, quotedNames(def), strings.Join(expected, ", "))
}

func quotedNames(def Definition) string {
	names := make([]string, 0, len(def.Actions))
	for _, action := range def.Actions {
		names = append(names, quote(permissionName(action, def.Name)))
	}
	return strings.Join(names, ", ")
}

func renderPermissionInsert(def Definition) string {
	values := make([]string, 0, len(def.Actions))
	for _, action := range def.Actions {
		values = append(values, fmt.Sprintf(
			"    (gen_random_uuid(), %s, %s, %s, %s)",
			quote(permissionName(action, def.Name)),
			quote(permissionDisplayName(action, def.DisplayName)),
			quote(def.Resource),
			quote(action),
		))
	}

	return fmt.Sprintf(
		"INSERT INTO permissions (id, name, display_name, resource, action) VALUES\n%s\nON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING;",
		strings.Join(values, ",\n"),
	)
}

func renderRolePermissionInsert(def Definition) string {
	quotedRoles := make([]string, 0, len(def.GrantRoles))
	for _, role := range def.GrantRoles {
		quotedRoles = append(quotedRoles, quote(role))
	}

	return fmt.Sprintf(
		"INSERT INTO role_permissions (role_id, permission_id)\nSELECT r.id, p.id\nFROM roles r\nJOIN permissions p ON p.resource = %s\nWHERE r.name IN (%s)\nON CONFLICT DO NOTHING;",
		quote(def.Resource),
		strings.Join(quotedRoles, ", "),
	)
}

func permissionName(action, moduleName string) string {
	return fmt.Sprintf("%s_%s", serviceshared.NormalizeKey(action), serviceshared.NormalizeKey(moduleName))
}

func permissionDisplayName(action, displayName string) string {
	return fmt.Sprintf("%s %s", serviceshared.TitleHumanized(action), displayName)
}

func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
