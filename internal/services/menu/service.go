package menu

import (
	"context"
	"time"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	dtomenu "github.com/zazhedho/authkit/internal/dto/menu"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

type Service struct {
	MenuRepo       Repository
	PermissionRepo PermissionRepository
}

func NewService(menuRepo Repository, permissionRepo PermissionRepository) *Service {
	return &Service{
		MenuRepo:       menuRepo,
		PermissionRepo: permissionRepo,
	}
}

func (s *Service) GetByID(ctx context.Context, id string) (domainmenu.MenuItem, error) {
	return s.MenuRepo.GetByID(ctx, id)
}

func (s *Service) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.MenuItem, int64, error) {
	return s.MenuRepo.GetAll(ctx, req)
}

func (s *Service) GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error) {
	return s.MenuRepo.GetActiveMenus(ctx)
}

func (s *Service) GetUserMenus(ctx context.Context, userID string) ([]domainmenu.MenuItem, error) {
	activeMenus, err := s.MenuRepo.GetActiveMenus(ctx)
	if err != nil {
		return nil, err
	}

	permissions, err := s.PermissionRepo.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	resources := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		if permission.Resource == "" {
			continue
		}
		resources = append(resources, permission.Resource)
	}

	return serviceshared.ResolveAccessibleMenus(activeMenus, resources), nil
}

func (s *Service) Update(ctx context.Context, id string, req dtomenu.MenuUpdate) (domainmenu.MenuItem, error) {
	menu, err := s.MenuRepo.GetByID(ctx, id)
	if err != nil {
		return domainmenu.MenuItem{}, err
	}

	if req.DisplayName != "" {
		menu.DisplayName = req.DisplayName
	}
	if req.Path != "" {
		menu.Path = req.Path
	}
	if req.Icon != "" {
		menu.Icon = req.Icon
	}
	if req.ParentID != nil {
		menu.ParentID = req.ParentID
	}
	if req.OrderIndex != nil {
		menu.OrderIndex = *req.OrderIndex
	}
	if req.IsActive != nil {
		menu.IsActive = *req.IsActive
	}
	menu.UpdatedAt = new(time.Now())

	if err := s.MenuRepo.Update(ctx, menu); err != nil {
		return domainmenu.MenuItem{}, err
	}

	return menu, nil
}
