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
	menu        domainmenu.MenuItem
	activeMenus []domainmenu.MenuItem
	updated     domainmenu.MenuItem
}

func (m *menuRepoTestDouble) Store(ctx context.Context, data domainmenu.MenuItem) error { return nil }
func (m *menuRepoTestDouble) GetByID(ctx context.Context, id string) (domainmenu.MenuItem, error) {
	if m.menu.ID == "" {
		return domainmenu.MenuItem{}, errors.New("not found")
	}
	return m.menu, nil
}
func (m *menuRepoTestDouble) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.MenuItem, int64, error) {
	return []domainmenu.MenuItem{m.menu}, 1, nil
}
func (m *menuRepoTestDouble) Update(ctx context.Context, data domainmenu.MenuItem) error {
	m.updated = data
	m.menu = data
	return nil
}
func (m *menuRepoTestDouble) Delete(ctx context.Context, id string) error { return nil }
func (m *menuRepoTestDouble) SoftDelete(ctx context.Context, id, deletedBy string) error {
	return nil
}
func (m *menuRepoTestDouble) GetByName(ctx context.Context, name string) (domainmenu.MenuItem, error) {
	for _, menu := range m.activeMenus {
		if menu.Name == name {
			return menu, nil
		}
	}
	return domainmenu.MenuItem{}, errors.New("not found")
}
func (m *menuRepoTestDouble) GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error) {
	return append([]domainmenu.MenuItem{}, m.activeMenus...), nil
}
func (m *menuRepoTestDouble) GetUserMenus(ctx context.Context, userID string) ([]domainmenu.MenuItem, error) {
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
		&menuRepoTestDouble{activeMenus: []domainmenu.MenuItem{
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
	parentID := "parent-1"
	repo := &menuRepoTestDouble{menu: domainmenu.MenuItem{
		ID:          "menu-1",
		Name:        "users",
		DisplayName: "Users",
		Path:        "/users",
		Icon:        "old-icon",
		IsActive:    true,
	}}
	svc := NewService(repo, &permissionRepoMenuTestDouble{})

	got, err := svc.Update(context.Background(), "menu-1", dtomenu.MenuUpdate{
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
		menu: domainmenu.MenuItem{ID: "menu-1", Name: "users", IsActive: true},
		activeMenus: []domainmenu.MenuItem{
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
