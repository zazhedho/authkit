package moduleseed

import (
	"strings"
	"testing"
)

func TestRenderSQLUsesConsistentResourceAndMenuName(t *testing.T) {
	sql, err := RenderSQL(Definition{
		Name:        "projects",
		DisplayName: "Projects",
		Path:        "/projects",
		Icon:        "bi-folder",
		OrderIndex:  905,
		Actions:     []string{"list", "view", "create", "update", "delete"},
		GrantRoles:  []string{"admin", "superadmin"},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	expectedFragments := []string{
		"'projects', 'Projects', '/projects', 'bi-folder', 905, TRUE",
		"'list_projects', 'List Projects', 'projects', 'list'",
		"'view_projects', 'View Projects', 'projects', 'view'",
		"JOIN permissions p ON p.resource = 'projects'",
		"WHERE r.name IN ('admin', 'superadmin')",
	}
	for _, fragment := range expectedFragments {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("expected SQL to contain %q\nSQL:\n%s", fragment, sql)
		}
	}
}

func TestRenderSQLSupportsParentMenu(t *testing.T) {
	sql, err := RenderSQL(Definition{
		Name:        "education_stats",
		DisplayName: "Education Stats",
		Path:        "/education/stats",
		Icon:        "bi-bar-chart",
		OrderIndex:  210,
		ParentName:  "education",
		Actions:     []string{"list", "view"},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if !strings.Contains(sql, "(SELECT id FROM menu_items WHERE name = 'education' AND deleted_at IS NULL LIMIT 1)") {
		t.Fatalf("expected parent_id subquery in SQL:\n%s", sql)
	}
}

func TestRenderSQLRejectsMissingRequiredFields(t *testing.T) {
	_, err := RenderSQL(Definition{Name: "projects"})
	if err == nil || err.Error() != "display_name is required" {
		t.Fatalf("expected display_name validation error, got %v", err)
	}
}

func TestRenderSQLUsesTheLiveUniqueIndexAndGuardsNameCollisions(t *testing.T) {
	sql, err := RenderSQL(Definition{Name: "projects", DisplayName: "Projects", Path: "/projects", GrantRoles: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(sql, "ON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING") != 2 {
		t.Fatalf("menu and permission inserts must target the partial unique index:\n%s", sql)
	}
	if !strings.Contains(sql, "RAISE EXCEPTION 'module-seed:") || !strings.Contains(sql, "('list_projects', 'projects', 'list')") {
		t.Fatalf("the collision guard is missing:\n%s", sql)
	}
}

func TestRenderSQLRejectsNamesThatCouldBreakOutOfTheGuardBlock(t *testing.T) {
	good := Definition{Name: "trips", DisplayName: "Trips", Path: "/trips"}
	for name, mutate := range map[string]func(*Definition){
		"dollar quote in name":     func(d *Definition) { d.Name = "trips$$; DROP TABLE users; --" },
		"dollar quote in resource": func(d *Definition) { d.Resource = "x$$y" },
		"tagged quote in action":   func(d *Definition) { d.Actions = []string{"list$authkit$"} },
		"quote in parent":          func(d *Definition) { d.ParentName = "a'b" },
		"space in role":            func(d *Definition) { d.GrantRoles = []string{"ad min"} },
		"semicolon in name":        func(d *Definition) { d.Name = "a;b" },
		"hyphen in action":         func(d *Definition) { d.Actions = []string{"bulk-delete"} },
	} {
		d := good
		mutate(&d)
		if _, err := RenderSQL(d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, d := range map[string]Definition{
		"kebab name":     {Name: "trip-plans", DisplayName: "Trips", Path: "/t"},
		"underscore":     {Name: "trip_plans", DisplayName: "Trips", Path: "/t", Actions: []string{"bulk_delete"}},
		"kebab resource": {Name: "trips", Resource: "trip-plans", DisplayName: "Trips", Path: "/t", GrantRoles: []string{"custom-role"}},
	} {
		if _, err := RenderSQL(d); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRenderSQLUsesATaggedQuoteForTheGuardBlock(t *testing.T) {
	sql, err := RenderSQL(Definition{Name: "trips", DisplayName: "Trips", Path: "/trips"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "$$") || !strings.Contains(sql, "DO $authkit$") || !strings.Contains(sql, "END$authkit$;") {
		t.Fatalf("the DO block must use the $authkit$ tag:\n%s", sql)
	}
}
