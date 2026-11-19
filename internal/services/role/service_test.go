package role

import (
	"context"
	"errors"
	"strings"
	"testing"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
)

func roleActor(userID, username, role string, permissions ...string) domainauth.Actor {
	return domainauth.ActorOf(domainauth.New(userID, username, role, permissions))
}

type roleRepoMock struct {
	role                domainrole.Role
	roles               []domainrole.Role
	existingByName      domainrole.Role
	rolePermissions     []string
	assignedPermissions []string
	stored              domainrole.Role
	updated             domainrole.Role
	deletedID           string
	usersWithRole       int64
}

func (m *roleRepoMock) CountUsers(ctx context.Context, roleID string) (int64, error) {
	return m.usersWithRole, nil
}

func (m *roleRepoMock) Store(ctx context.Context, data domainrole.Role) error {
	m.stored = data
	return nil
}
func (m *roleRepoMock) GetByID(ctx context.Context, id string) (domainrole.Role, error) {
	return m.role, nil
}
func (m *roleRepoMock) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainrole.Role, int64, error) {
	return append([]domainrole.Role{}, m.roles...), int64(len(m.roles)), nil
}
func (m *roleRepoMock) Update(ctx context.Context, data domainrole.Role) error {
	m.updated = data
	return nil
}
func (m *roleRepoMock) Delete(ctx context.Context, id string) error {
	m.deletedID = id
	return nil
}
func (m *roleRepoMock) SoftDelete(ctx context.Context, id, deletedBy string) error {
	m.deletedID = id
	return nil
}
func (m *roleRepoMock) GetByName(ctx context.Context, name string) (domainrole.Role, error) {
	return m.existingByName, nil
}
func (m *roleRepoMock) AssignPermissions(ctx context.Context, roleID string, permissionIDs []string) error {
	m.assignedPermissions = append([]string{}, permissionIDs...)
	return nil
}
func (m *roleRepoMock) GetRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	return m.rolePermissions, nil
}

type permissionRepoMock struct {
	permissionsByID map[string]domainpermission.Permission
	userPermissions []domainpermission.Permission
}

func (m *permissionRepoMock) Store(ctx context.Context, data domainpermission.Permission) error {
	return nil
}
func (m *permissionRepoMock) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	permission, ok := m.permissionsByID[id]
	if !ok {
		return domainpermission.Permission{}, errors.New("not found")
	}
	return permission, nil
}
func (m *permissionRepoMock) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainpermission.Permission, int64, error) {
	return nil, 0, nil
}
func (m *permissionRepoMock) Update(ctx context.Context, data domainpermission.Permission) error {
	return nil
}
func (m *permissionRepoMock) Delete(ctx context.Context, id string) error { return nil }
func (m *permissionRepoMock) SoftDelete(ctx context.Context, id, deletedBy string) error {
	return nil
}
func (m *permissionRepoMock) GetByName(ctx context.Context, name string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoMock) GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error) {
	return nil, nil
}
func (m *permissionRepoMock) GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error) {
	return append([]domainpermission.Permission{}, m.userPermissions...), nil
}

type menuRepoMock struct {
	activeMenus []domainmenu.Item
}

func (m *menuRepoMock) Store(ctx context.Context, data domainmenu.Item) error { return nil }
func (m *menuRepoMock) GetByID(ctx context.Context, id string) (domainmenu.Item, error) {
	return domainmenu.Item{}, errors.New("not implemented")
}
func (m *menuRepoMock) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.Item, int64, error) {
	return nil, 0, nil
}
func (m *menuRepoMock) Update(ctx context.Context, data domainmenu.Item) error { return nil }
func (m *menuRepoMock) Delete(ctx context.Context, id string) error            { return nil }
func (m *menuRepoMock) SoftDelete(ctx context.Context, id, deletedBy string) error {
	return nil
}
func (m *menuRepoMock) GetByName(ctx context.Context, name string) (domainmenu.Item, error) {
	return domainmenu.Item{}, errors.New("not implemented")
}
func (m *menuRepoMock) GetActiveMenus(ctx context.Context) ([]domainmenu.Item, error) {
	return append([]domainmenu.Item{}, m.activeMenus...), nil
}
func (m *menuRepoMock) GetUserMenus(ctx context.Context, userID string) ([]domainmenu.Item, error) {
	return nil, nil
}

func TestAssignPermissionsRequiresManageSystemPermissionForSystemRole(t *testing.T) {
	service := &Service{
		RoleRepo: &roleRepoMock{
			role: domainrole.Role{ID: "role-1", Name: domainuser.RoleAdmin, IsSystem: true},
		},
		PermissionRepo: &permissionRepoMock{},
		MenuRepo:       &menuRepoMock{},
	}

	err := service.AssignPermissions(context.Background(), roleActor("user-1", "Staff User", domainuser.RoleStaff), "role-1", dtorole.AssignPermissions{PermissionIDs: []string{"perm-1"}})
	if err == nil || err.Error() != "access denied: missing permission roles:manage_system" {
		t.Fatalf("expected manage_system access error, got %v", err)
	}
}

func TestAssignPermissionsRejectsSuperadminRoleForNonSuperadmin(t *testing.T) {
	service := &Service{
		RoleRepo: &roleRepoMock{
			role: domainrole.Role{ID: "role-1", Name: domainuser.RoleSuperAdmin, IsSystem: true},
		},
		PermissionRepo: &permissionRepoMock{
			userPermissions: []domainpermission.Permission{{Resource: "roles", Action: "manage_system"}},
		},
		MenuRepo: &menuRepoMock{},
	}

	err := service.AssignPermissions(context.Background(), roleActor("user-1", "Admin User", domainuser.RoleAdmin, "roles:manage_system"), "role-1", dtorole.AssignPermissions{PermissionIDs: []string{"perm-1"}})
	if err == nil || err.Error() != "access denied: cannot modify superadmin role" {
		t.Fatalf("expected superadmin protection error, got %v", err)
	}
}

func TestAssignPermissionsAllowsSystemRoleWhenPermissionPresent(t *testing.T) {
	roleRepo := &roleRepoMock{
		role: domainrole.Role{ID: "role-1", Name: domainuser.RoleAdmin, IsSystem: true},
	}
	service := &Service{
		RoleRepo: roleRepo,
		PermissionRepo: &permissionRepoMock{
			userPermissions: []domainpermission.Permission{{Resource: "roles", Action: "manage_system"}},
			permissionsByID: map[string]domainpermission.Permission{
				"perm-1": {ID: "perm-1", Resource: "users", Action: "view"},
			},
		},
		MenuRepo: &menuRepoMock{},
	}

	err := service.AssignPermissions(context.Background(), roleActor("user-1", "Admin User", domainuser.RoleAdmin, "roles:manage_system", "users:view"), "role-1", dtorole.AssignPermissions{PermissionIDs: []string{"perm-1"}})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if len(roleRepo.assignedPermissions) != 1 || roleRepo.assignedPermissions[0] != "perm-1" {
		t.Fatalf("expected assigned permission to be stored, got %v", roleRepo.assignedPermissions)
	}
}

func TestRoleServiceCRUDAndDetails(t *testing.T) {
	roleRepo := &roleRepoMock{
		role: domainrole.Role{ID: "role-1", Name: "manager", DisplayName: "Manager"},
		roles: []domainrole.Role{
			{ID: "role-1", Name: "manager"},
			{ID: "role-2", Name: domainuser.RoleSuperAdmin},
		},
		rolePermissions: []string{"perm-1"},
	}
	parentID := "menu-root"
	service := NewService(roleRepo, &permissionRepoMock{
		permissionsByID: map[string]domainpermission.Permission{
			"perm-1": {ID: "perm-1", Resource: "users", Action: "view"},
		},
	}, &menuRepoMock{activeMenus: []domainmenu.Item{
		{ID: parentID, Name: "root", DisplayName: "Root", IsActive: true},
		{ID: "menu-users", Name: "users", DisplayName: "Users", ParentID: &parentID, IsActive: true},
	}})

	created, err := service.Create(context.Background(), dtorole.Create{Name: "manager", DisplayName: "Manager", Description: "Can manage users"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" || roleRepo.stored.Name != "manager" {
		t.Fatalf("expected created role to be stored, role=%+v stored=%+v", created, roleRepo.stored)
	}

	got, err := service.GetByID(context.Background(), "role-1")
	if err != nil || got.ID != "role-1" {
		t.Fatalf("get by id: role=%+v err=%v", got, err)
	}

	details, err := service.GetByIDWithDetails(context.Background(), "role-1")
	if err != nil {
		t.Fatalf("get details: %v", err)
	}
	if len(details.PermissionIDs) != 1 || len(details.MenuIDs) != 2 {
		t.Fatalf("unexpected details: %+v", details)
	}

	roles, total, err := service.GetAll(context.Background(), roleActor("user-1", "Staff", domainuser.RoleStaff), dtoshared.ListRequest{})
	if err != nil {
		t.Fatalf("get all: %v", err)
	}
	if total != 1 || len(roles) != 1 || roles[0].Name == domainuser.RoleSuperAdmin {
		t.Fatalf("expected superadmin filtered for non-superadmin, roles=%+v total=%d", roles, total)
	}

	updated, err := service.Update(context.Background(), "role-1", dtorole.Update{DisplayName: "Updated", Description: "Updated desc"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.DisplayName != "Updated" || roleRepo.updated.DisplayName != "Updated" {
		t.Fatalf("expected updated role, got %+v stored %+v", updated, roleRepo.updated)
	}

	if err := service.Delete(context.Background(), "role-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if roleRepo.deletedID != "role-1" {
		t.Fatalf("expected role deletion, got %q", roleRepo.deletedID)
	}

	permissionIDs, err := service.GetRolePermissions(context.Background(), "role-1")
	if err != nil || len(permissionIDs) != 1 || permissionIDs[0] != "perm-1" {
		t.Fatalf("get role permissions: ids=%+v err=%v", permissionIDs, err)
	}
}

func TestRoleServiceSystemRoleProtections(t *testing.T) {
	systemRepo := &roleRepoMock{role: domainrole.Role{ID: "role-1", Name: domainuser.RoleAdmin, IsSystem: true}}
	service := NewService(systemRepo, &permissionRepoMock{}, &menuRepoMock{})

	if _, err := service.Update(context.Background(), "role-1", dtorole.Update{DisplayName: "Updated"}); err == nil {
		t.Fatal("expected system role update to be rejected")
	}
	if err := service.Delete(context.Background(), "role-1"); err == nil {
		t.Fatal("expected system role delete to be rejected")
	}
}

func TestRoleServiceCreateRejectsDuplicateAndInvalidPermission(t *testing.T) {
	duplicateService := NewService(&roleRepoMock{existingByName: domainrole.Role{ID: "role-1", Name: "manager"}}, &permissionRepoMock{}, &menuRepoMock{})
	if _, err := duplicateService.Create(context.Background(), dtorole.Create{Name: "manager"}); err == nil {
		t.Fatal("expected duplicate role error")
	}

	service := NewService(&roleRepoMock{role: domainrole.Role{ID: "role-1", Name: "manager"}}, &permissionRepoMock{}, &menuRepoMock{})
	err := service.AssignPermissions(context.Background(), roleActor("user-1", "Admin User", domainuser.RoleAdmin), "role-1", dtorole.AssignPermissions{PermissionIDs: []string{"missing"}})
	if err == nil || err.Error() != "invalid permission ID: missing" {
		t.Fatalf("expected invalid permission error, got %v", err)
	}
}

// Regression: the old StripHTML unescaped entities after stripping tags, so
// this input was stored as a live <script> element. Text is now stored as the
// trimmed raw input and never HTML-processed.
func TestRoleServiceCreateDoesNotTurnEntitiesIntoMarkup(t *testing.T) {
	roleRepo := &roleRepoMock{}
	service := NewService(roleRepo, &permissionRepoMock{}, &menuRepoMock{})

	payload := "&lt;script&gt;alert(1)&lt;/script&gt;"
	_, err := service.Create(context.Background(), dtorole.Create{Name: "  " + payload + " ", DisplayName: payload, Description: " " + payload})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for field, got := range map[string]string{"name": roleRepo.stored.Name, "display_name": roleRepo.stored.DisplayName, "description": roleRepo.stored.Description} {
		if got != payload {
			t.Errorf("%s = %q, want the trimmed raw input %q", field, got, payload)
		}
		if strings.Contains(got, "<script") {
			t.Errorf("%s holds live markup: %q", field, got)
		}
	}
}

func TestAssignPermissionsMayOnlyGrantWhatTheActorHolds(t *testing.T) {
	roleRepo := &roleRepoMock{role: domainrole.Role{ID: "role-1", Name: "custom"}}
	service := &Service{
		RoleRepo: roleRepo,
		PermissionRepo: &permissionRepoMock{permissionsByID: map[string]domainpermission.Permission{
			"p-view":  {ID: "p-view", Resource: "users", Action: "view"},
			"p-super": {ID: "p-super", Resource: "roles", Action: "manage_system"},
		}},
		MenuRepo: &menuRepoMock{},
	}
	actor := roleActor("u", "U", domainuser.RoleStaff, "users:view", "roles:assign_permissions")

	err := service.AssignPermissions(context.Background(), actor, "role-1", dtorole.AssignPermissions{PermissionIDs: []string{"p-view", "p-super"}})
	if !errors.Is(err, domainuser.ErrRoleAboveActor) {
		t.Fatalf("got %v, want ErrRoleAboveActor", err)
	}
	if roleRepo.assignedPermissions != nil {
		t.Fatal("nothing may be assigned when one permission is not held")
	}
}

func TestAssignPermissionsDedupesAndAllowsAnEmptyList(t *testing.T) {
	roleRepo := &roleRepoMock{role: domainrole.Role{ID: "role-1", Name: "custom"}}
	service := &Service{
		RoleRepo: roleRepo,
		PermissionRepo: &permissionRepoMock{permissionsByID: map[string]domainpermission.Permission{
			"p-view": {ID: "p-view", Resource: "users", Action: "view"},
		}},
		MenuRepo: &menuRepoMock{},
	}
	actor := roleActor("u", "U", domainuser.RoleStaff, "users:view")
	if err := service.AssignPermissions(context.Background(), actor, "role-1", dtorole.AssignPermissions{PermissionIDs: []string{"p-view", "p-view"}}); err != nil {
		t.Fatal(err)
	}
	if len(roleRepo.assignedPermissions) != 1 {
		t.Fatalf("got %v, want one id", roleRepo.assignedPermissions)
	}
	roleRepo.assignedPermissions = []string{"stale"}
	if err := service.AssignPermissions(context.Background(), actor, "role-1", dtorole.AssignPermissions{PermissionIDs: []string{}}); err != nil {
		t.Fatal(err)
	}
	if len(roleRepo.assignedPermissions) != 0 {
		t.Fatalf("empty list must clear the role, got %v", roleRepo.assignedPermissions)
	}
}

func TestDeleteRefusesARoleThatUsersStillHold(t *testing.T) {
	roleRepo := &roleRepoMock{role: domainrole.Role{ID: "role-1", Name: "custom"}, usersWithRole: 2}
	service := &Service{RoleRepo: roleRepo, PermissionRepo: &permissionRepoMock{}, MenuRepo: &menuRepoMock{}}
	if err := service.Delete(context.Background(), "role-1"); !errors.Is(err, domainrole.ErrInUse) {
		t.Fatalf("got %v, want ErrInUse", err)
	}
	if roleRepo.deletedID != "" {
		t.Fatal("role must not be deleted")
	}
}

func TestCreateLowercasesTheRoleName(t *testing.T) {
	roleRepo := &roleRepoMock{}
	service := &Service{RoleRepo: roleRepo, PermissionRepo: &permissionRepoMock{}, MenuRepo: &menuRepoMock{}}
	got, err := service.Create(context.Background(), dtorole.Create{Name: " Support Lead ", DisplayName: "Support"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "support_lead" && got.Name != "support lead" {
		t.Fatalf("unexpected name %q", got.Name)
	}
	if got.Name != strings.ToLower(got.Name) {
		t.Fatalf("name %q is not lowercase", got.Name)
	}
}
