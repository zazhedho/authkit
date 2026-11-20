package menu

import (
	"context"
	"errors"
	"testing"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	dtomenu "github.com/zazhedho/authkit/internal/dto/menu"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
)

type menuRepoTestDouble struct {
	menu        domainmenu.Item
	byID        map[string]domainmenu.Item
	activeMenus []domainmenu.Item
	updated     domainmenu.Item
}

func (m *menuRepoTestDouble) Store(ctx context.Context, data domainmenu.Item) error { return nil }
func (m *menuRepoTestDouble) GetByID(ctx context.Context, id string) (domainmenu.Item, error) {
	if m.byID != nil {
		if item, ok := m.byID[id]; ok {
			return item, nil
		}
		return domainmenu.Item{}, domainmenu.ErrNotFound
	}
	if m.menu.ID == "" {
		return domainmenu.Item{}, errors.New("not found")
	}
	return m.menu, nil
}
func (m *menuRepoTestDouble) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.Item, int64, error) {
	return []domainmenu.Item{m.menu}, 1, nil
}
func (m *menuRepoTestDouble) Update(ctx context.Context, data domainmenu.Item) error {
	m.updated = data
	m.menu = data
	return nil
}
func (m *menuRepoTestDouble) Delete(ctx context.Context, id string) error { return nil }
func (m *menuRepoTestDouble) SoftDelete(ctx context.Context, id, deletedBy string) error {
	return nil
}
func (m *menuRepoTestDouble) GetByName(ctx context.Context, name string) (domainmenu.Item, error) {
	for _, menu := range m.activeMenus {
		if menu.Name == name {
			return menu, nil
		}
	}
	return domainmenu.Item{}, errors.New("not found")
}
func (m *menuRepoTestDouble) GetActiveMenus(ctx context.Context) ([]domainmenu.Item, error) {
	return append([]domainmenu.Item{}, m.activeMenus...), nil
}
func (m *menuRepoTestDouble) GetUserMenus(ctx context.Context, userID string) ([]domainmenu.Item, error) {
	return nil, nil
}

type permissionRepoMenuTestDouble struct {
	userPermissions []domainpermission.Permission
}

func (m *permissionRepoMenuTestDouble) Store(ctx context.Context, data domainpermission.Permission) error {
	return nil
}
func (m *permissionRepoMenuTestDouble) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoMenuTestDouble) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainpermission.Permission, int64, error) {
	return nil, 0, nil
}
func (m *permissionRepoMenuTestDouble) Update(ctx context.Context, data domainpermission.Permission) error {
	return nil
}
func (m *permissionRepoMenuTestDouble) Delete(ctx context.Context, id string) error { return nil }
func (m *permissionRepoMenuTestDouble) SoftDelete(ctx context.Context, id, deletedBy string) error {
	return nil
}
func (m *permissionRepoMenuTestDouble) GetByName(ctx context.Context, name string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoMenuTestDouble) GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error) {
	return nil, nil
}
func (m *permissionRepoMenuTestDouble) GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error) {
	return append([]domainpermission.Permission{}, m.userPermissions...), nil
}

func TestGetUserMenusDerivesMenusFromPermissionResources(t *testing.T) {
	svc := NewService(
		&menuRepoTestDouble{activeMenus: []domainmenu.Item{
			{ID: "dashboard", Name: "dashboard", IsActive: true},
			{ID: "users", Name: "users", ParentID: new("settings"), IsActive: true},
			{ID: "settings", Name: "settings", IsActive: true},
		}},
		&permissionRepoMenuTestDouble{
			userPermissions: []domainpermission.Permission{{Resource: "users", Action: "list"}},
		},
	)

	got, err := svc.GetUserMenus(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected child and parent menus, got %+v", got)
	}
	if got[0].ID != "users" || got[1].ID != "settings" {
		t.Fatalf("unexpected menus: %+v", got)
	}
}

func TestUpdateOnlyAppliesProvidedMenuFields(t *testing.T) {
	orderIndex := 42
	parentID := "550e8400-e29b-41d4-a716-4466554400a1"
	existing := domainmenu.Item{
		ID:          "menu-1",
		Name:        "users",
		DisplayName: "Users",
		Path:        "/users",
		Icon:        "old-icon",
		IsActive:    true,
	}
	repo := &menuRepoTestDouble{menu: existing, byID: map[string]domainmenu.Item{"menu-1": existing, parentID: {ID: parentID}}}
	svc := NewService(repo, &permissionRepoMenuTestDouble{})

	got, err := svc.Update(context.Background(), "menu-1", dtomenu.Update{
		DisplayName: "User Management",
		ParentID:    &parentID,
		OrderIndex:  &orderIndex,
		IsActive:    new(false),
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if got.DisplayName != "User Management" {
		t.Fatalf("expected display name to update, got %q", got.DisplayName)
	}
	if got.Path != "/users" || got.Icon != "old-icon" {
		t.Fatalf("expected empty request fields to preserve old values, got %+v", got)
	}
	if got.ParentID == nil || *got.ParentID != parentID || got.OrderIndex != orderIndex || got.IsActive {
		t.Fatalf("expected pointer fields to update, got %+v", got)
	}
	if got.UpdatedAt == nil {
		t.Fatal("expected updated_at to be set")
	}
}

func TestMenuServicePassThroughMethods(t *testing.T) {
	repo := &menuRepoTestDouble{
		menu: domainmenu.Item{ID: "menu-1", Name: "users", IsActive: true},
		activeMenus: []domainmenu.Item{
			{ID: "menu-1", Name: "users", IsActive: true},
		},
	}
	svc := NewService(repo, &permissionRepoMenuTestDouble{})

	if got, err := svc.GetByID(context.Background(), "menu-1"); err != nil || got.ID != "menu-1" {
		t.Fatalf("get by id: menu=%+v err=%v", got, err)
	}
	if got, total, err := svc.GetAll(context.Background(), dtoshared.ListRequest{}); err != nil || total != 1 || len(got) != 1 {
		t.Fatalf("get all: menus=%+v total=%d err=%v", got, total, err)
	}
	if got, err := svc.GetActiveMenus(context.Background()); err != nil || len(got) != 1 {
		t.Fatalf("get active menus: menus=%+v err=%v", got, err)
	}
}

func TestUpdateValidatesTheParent(t *testing.T) {
	const a, b, c = "550e8400-e29b-41d4-a716-4466554400a1", "550e8400-e29b-41d4-a716-4466554400b2", "550e8400-e29b-41d4-a716-4466554400c3"
	pa, pb := a, b
	repo := &menuRepoTestDouble{byID: map[string]domainmenu.Item{
		a: {ID: a},
		b: {ID: b, ParentID: &pa}, // b is a child of a
		c: {ID: c, ParentID: &pb}, // c is a child of b
	}}
	svc := NewService(repo, &permissionRepoMenuTestDouble{})
	set := func(id, parent string) error {
		_, err := svc.Update(context.Background(), id, dtomenu.Update{ParentID: &parent})
		return err
	}
	for name, tc := range map[string]struct{ id, parent string }{
		"not a uuid":           {a, "nope"},
		"itself":               {a, a},
		"missing parent":       {a, "550e8400-e29b-41d4-a716-4466554400ff"},
		"direct loop":          {a, b},
		"loop through a chain": {a, c},
	} {
		if err := set(tc.id, tc.parent); !errors.Is(err, domainmenu.ErrInvalidParent) {
			t.Errorf("%s: err = %v, want ErrInvalidParent", name, err)
		}
	}
	if err := set(c, a); err != nil {
		t.Errorf("a valid re-parent failed: %v", err)
	}
	if err := set(b, ""); err != nil || repo.updated.ParentID != nil {
		t.Errorf("an empty parent_id must clear the parent: err=%v parent=%v", err, repo.updated.ParentID)
	}
}

func TestUpdateCleansTextFields(t *testing.T) {
	existing := domainmenu.Item{ID: "menu-1", Name: "users", DisplayName: "Users"}
	repo := &menuRepoTestDouble{menu: existing}
	svc := NewService(repo, &permissionRepoMenuTestDouble{})

	got, err := svc.Update(context.Background(), "menu-1", dtomenu.Update{DisplayName: "  Team ", Path: " /team\t", Icon: " bi-x\n"})
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Team" || got.Path != "/team" || got.Icon != "bi-x" {
		t.Fatalf("fields not cleaned: %+v", got)
	}
}
