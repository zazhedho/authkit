package menu

import (
	"context"
	"time"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	dtomenu "github.com/zazhedho/authkit/internal/dto/menu"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

// Service implements the menu use cases.
type Service struct {
	MenuRepo       Repository
	PermissionRepo PermissionRepository
}

// NewService creates the menu service.
func NewService(menuRepo Repository, permissionRepo PermissionRepository) *Service {
	return &Service{
		MenuRepo:       menuRepo,
		PermissionRepo: permissionRepo,
	}
}

// GetByID returns one record found by ID.
func (s *Service) GetByID(ctx context.Context, id string) (domainmenu.Item, error) {
	return s.MenuRepo.GetByID(ctx, id)
}

// GetAll returns a page of records.
func (s *Service) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.Item, int64, error) {
	return s.MenuRepo.GetAll(ctx, req)
}

// GetActiveMenus returns the active menus.
func (s *Service) GetActiveMenus(ctx context.Context) ([]domainmenu.Item, error) {
	return s.MenuRepo.GetActiveMenus(ctx)
}

// GetUserMenus returns the user menus.
func (s *Service) GetUserMenus(ctx context.Context, userID string) ([]domainmenu.Item, error) {
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

// Update updates the record.
func (s *Service) Update(ctx context.Context, id string, req dtomenu.Update) (domainmenu.Item, error) {
	menu, err := s.MenuRepo.GetByID(ctx, id)
	if err != nil {
		return domainmenu.Item{}, err
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
		return domainmenu.Item{}, err
	}

	return menu, nil
}
