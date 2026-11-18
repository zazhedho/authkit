package role

import (
	"context"
	"errors"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
	"time"
)

type Service struct {
	RoleRepo        Repository
	PermissionRepo  PermissionRepository
	MenuRepo        MenuRepository
	PermissionCache PermissionCache
	// NewID makes record ids; nil uses a UUID v7.
	NewID func() string
}

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

func (s *Service) Create(ctx context.Context, req dtorole.RoleCreate) (domainrole.Role, error) {
	existing, _ := s.RoleRepo.GetByName(ctx, req.Name)
	if existing.Id != "" {
		return domainrole.Role{}, errors.New("role with this name already exists")
	}

	data := domainrole.Role{
		Id:          s.newID(),
		Name:        serviceshared.StripHTML(req.Name),
		DisplayName: serviceshared.StripHTML(req.DisplayName),
		Description: serviceshared.StripHTML(req.Description),
		IsSystem:    false,
		CreatedAt:   time.Now(),
	}

	if err := s.RoleRepo.Store(ctx, data); err != nil {
		return domainrole.Role{}, err
	}

	return data, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (domainrole.Role, error) {
	return s.RoleRepo.GetByID(ctx, id)
}

func (s *Service) GetByIDWithDetails(ctx context.Context, id string) (dtorole.RoleWithDetails, error) {
	role, err := s.RoleRepo.GetByID(ctx, id)
	if err != nil {
		return dtorole.RoleWithDetails{}, err
	}

	permissionIds, err := s.RoleRepo.GetRolePermissions(ctx, id)
	if err != nil {
		return dtorole.RoleWithDetails{}, err
	}

	menuIds, err := s.deriveMenuIDsFromPermissions(ctx, permissionIds)
	if err != nil {
		return dtorole.RoleWithDetails{}, err
	}

	updatedAt := ""
	if role.UpdatedAt != nil {
		updatedAt = role.UpdatedAt.Format(time.RFC3339)
	}

	return dtorole.RoleWithDetails{
		Id:            role.Id,
		Name:          role.Name,
		DisplayName:   role.DisplayName,
		Description:   role.Description,
		IsSystem:      role.IsSystem,
		PermissionIds: permissionIds,
		MenuIds:       menuIds,
		CreatedAt:     role.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     updatedAt,
	}, nil
}

func (s *Service) GetAll(ctx context.Context, actor domainauth.Actor, req dtoshared.ListRequest) ([]domainrole.Role, int64, error) {
	roles, total, err := s.RoleRepo.GetAll(ctx, req)
	if err != nil {
		return nil, 0, err
	}

	if actor.Role != domainuser.RoleSuperAdmin {
		filteredRoles := make([]domainrole.Role, 0)
		for _, role := range roles {
			if role.Name != domainuser.RoleSuperAdmin {
				filteredRoles = append(filteredRoles, role)
			}
		}
		superadminCount := int64(len(roles) - len(filteredRoles))
		return filteredRoles, total - superadminCount, nil
	}

	return roles, total, nil
}

func (s *Service) Update(ctx context.Context, id string, req dtorole.RoleUpdate) (domainrole.Role, error) {
	role, err := s.RoleRepo.GetByID(ctx, id)
	if err != nil {
		return domainrole.Role{}, err
	}

	if role.IsSystem {
		return domainrole.Role{}, errors.New("cannot update system roles")
	}

	if req.DisplayName != "" {
		role.DisplayName = serviceshared.StripHTML(req.DisplayName)
	}
	role.Description = serviceshared.StripHTML(req.Description)
	role.UpdatedAt = new(time.Now())

	if err := s.RoleRepo.Update(ctx, role); err != nil {
		return domainrole.Role{}, err
	}

	return role, nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	role, err := s.RoleRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	if role.IsSystem {
		return errors.New("cannot delete system roles")
	}

	if err := s.RoleRepo.Delete(ctx, id); err != nil {
		return err
	}
	s.invalidatePermissionCache(ctx)
	return nil
}

func (s *Service) AssignPermissions(ctx context.Context, actor domainauth.Actor, roleId string, req dtorole.AssignPermissions) error {
	role, err := s.RoleRepo.GetByID(ctx, roleId)
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

	for _, permId := range req.PermissionIds {
		if _, err := s.PermissionRepo.GetByID(ctx, permId); err != nil {
			return errors.New("invalid permission ID: " + permId)
		}
	}

	if err := s.RoleRepo.AssignPermissions(ctx, roleId, req.PermissionIds); err != nil {
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

func (s *Service) GetRolePermissions(ctx context.Context, roleId string) ([]string, error) {
	return s.RoleRepo.GetRolePermissions(ctx, roleId)
}

func (s *Service) deriveMenuIDsFromPermissions(ctx context.Context, permissionIds []string) ([]string, error) {
	resources := make([]string, 0, len(permissionIds))

	for _, permissionId := range permissionIds {
		permission, err := s.PermissionRepo.GetByID(ctx, permissionId)
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
