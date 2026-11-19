package role

import (
	"context"
	"errors"
	"time"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

// Service implements the role use cases.
type Service struct {
	RoleRepo        Repository
	PermissionRepo  PermissionRepository
	MenuRepo        MenuRepository
	PermissionCache PermissionCache
	// NewID makes record ids; nil uses a UUID v7.
	NewID func() string
}

// NewService creates the role service.
func NewService(
	roleRepo Repository,
	permissionRepo PermissionRepository,
	menuRepo MenuRepository,
	invalidators ...PermissionCache,
) *Service {
	service := &Service{
		RoleRepo:       roleRepo,
		PermissionRepo: permissionRepo,
		MenuRepo:       menuRepo,
		NewID:          serviceshared.NewID,
	}
	if len(invalidators) > 0 {
		service.PermissionCache = invalidators[0]
	}
	return service
}

// Create creates the record.
func (s *Service) Create(ctx context.Context, req dtorole.Create) (domainrole.Role, error) {
	name := serviceshared.NormalizeKey(serviceshared.CleanText(req.Name))
	existing, err := s.RoleRepo.GetByName(ctx, name)
	if err != nil && !errors.Is(err, domainrole.ErrNotFound) {
		return domainrole.Role{}, err
	}
	if existing.ID != "" {
		return domainrole.Role{}, errors.New("role with this name already exists")
	}

	data := domainrole.Role{
		ID:          s.newID(),
		Name:        name,
		DisplayName: serviceshared.CleanText(req.DisplayName),
		Description: serviceshared.CleanText(req.Description),
		IsSystem:    false,
		CreatedAt:   time.Now(),
	}

	if err := s.RoleRepo.Store(ctx, data); err != nil {
		return domainrole.Role{}, err
	}

	return data, nil
}

// GetByID returns one record found by ID.
func (s *Service) GetByID(ctx context.Context, id string) (domainrole.Role, error) {
	return s.RoleRepo.GetByID(ctx, id)
}

// GetByIDWithDetails returns one record found by ID with details.
func (s *Service) GetByIDWithDetails(ctx context.Context, id string) (dtorole.WithDetails, error) {
	role, err := s.RoleRepo.GetByID(ctx, id)
	if err != nil {
		return dtorole.WithDetails{}, err
	}

	permissionIDs, err := s.RoleRepo.GetRolePermissions(ctx, id)
	if err != nil {
		return dtorole.WithDetails{}, err
	}

	menuIDs, err := s.deriveMenuIDsFromPermissions(ctx, permissionIDs)
	if err != nil {
		return dtorole.WithDetails{}, err
	}

	updatedAt := ""
	if role.UpdatedAt != nil {
		updatedAt = role.UpdatedAt.Format(time.RFC3339)
	}

	return dtorole.WithDetails{
		ID:            role.ID,
		Name:          role.Name,
		DisplayName:   role.DisplayName,
		Description:   role.Description,
		IsSystem:      role.IsSystem,
		PermissionIDs: permissionIDs,
		MenuIDs:       menuIDs,
		CreatedAt:     role.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     updatedAt,
	}, nil
}

// GetAll returns a page of records.
func (s *Service) GetAll(ctx context.Context, actor domainauth.Actor, req dtoshared.ListRequest) ([]domainrole.Role, int64, error) {
	roles, total, err := s.RoleRepo.GetAll(ctx, req)
	return serviceshared.HideSuperAdmin(actor, roles, total, err, func(role domainrole.Role) bool {
		return role.Name == domainuser.RoleSuperAdmin
	})
}

// Update updates the record.
func (s *Service) Update(ctx context.Context, id string, req dtorole.Update) (domainrole.Role, error) {
	role, err := s.RoleRepo.GetByID(ctx, id)
	if err != nil {
		return domainrole.Role{}, err
	}

	if role.IsSystem {
		return domainrole.Role{}, errors.New("cannot update system roles")
	}

	if req.DisplayName != "" {
		role.DisplayName = serviceshared.CleanText(req.DisplayName)
	}
	role.Description = serviceshared.CleanText(req.Description)
	role.UpdatedAt = new(time.Now())

	if err := s.RoleRepo.Update(ctx, role); err != nil {
		return domainrole.Role{}, err
	}

	return role, nil
}

// Delete deletes the record.
func (s *Service) Delete(ctx context.Context, id string) error {
	role, err := s.RoleRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if role.IsSystem {
		return errors.New("cannot delete system roles")
	}
	users, err := s.RoleRepo.CountUsers(ctx, id)
	if err != nil {
		return err
	}
	if users > 0 {
		return domainrole.ErrInUse
	}

	if err := s.RoleRepo.Delete(ctx, id); err != nil {
		return err
	}
	s.invalidatePermissionCache(ctx)
	return nil
}

// AssignPermissions assigns the permissions.
func (s *Service) AssignPermissions(ctx context.Context, actor domainauth.Actor, roleID string, req dtorole.AssignPermissions) error {
	role, err := s.RoleRepo.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	if role.IsSystem {
		canManageSystem, err := serviceshared.HasPermission(ctx, s.PermissionRepo, actor, "roles", "manage_system")
		if err != nil {
			return err
		}
		if !canManageSystem {
			return errors.New("access denied: missing permission roles:manage_system")
		}
		if role.Name == domainuser.RoleSuperAdmin && actor.Role != domainuser.RoleSuperAdmin {
			return errors.New("access denied: cannot modify superadmin role")
		}
	}

	permissionIDs := dedupe(req.PermissionIDs)
	for _, permID := range permissionIDs {
		permission, err := s.PermissionRepo.GetByID(ctx, permID)
		if err != nil {
			return errors.New("invalid permission ID: " + permID)
		}
		// An actor may only grant what they hold, so assign_permissions cannot
		// be used to climb above the actor's own role.
		if !actor.Has(permission.Resource, permission.Action) {
			return domainuser.ErrRoleAboveActor
		}
	}

	if err := s.RoleRepo.AssignPermissions(ctx, roleID, permissionIDs); err != nil {
		return err
	}
	s.invalidatePermissionCache(ctx)
	return nil
}

func (s *Service) invalidatePermissionCache(ctx context.Context) {
	if s.PermissionCache != nil {
		s.PermissionCache.DeleteAll(ctx)
	}
}

// GetRolePermissions returns the role permissions.
func (s *Service) GetRolePermissions(ctx context.Context, roleID string) ([]string, error) {
	return s.RoleRepo.GetRolePermissions(ctx, roleID)
}

func (s *Service) deriveMenuIDsFromPermissions(ctx context.Context, permissionIDs []string) ([]string, error) {
	resources := make([]string, 0, len(permissionIDs))

	for _, permissionID := range permissionIDs {
		permission, err := s.PermissionRepo.GetByID(ctx, permissionID)
		if err != nil {
			return nil, err
		}

		if permission.Resource == "" {
			continue
		}

		resources = append(resources, permission.Resource)
	}

	activeMenus, err := s.MenuRepo.GetActiveMenus(ctx)
	if err != nil {
		return nil, err
	}

	return serviceshared.ResolveAccessibleMenuIDs(activeMenus, resources), nil
}

func (s *Service) newID() string {
	if s.NewID != nil {
		return s.NewID()
	}
	return serviceshared.NewID()
}

func dedupe(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
