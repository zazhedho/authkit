package menu

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

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

func (s *Service) GetByID(ctx context.Context, id string) (domainmenu.Item, error) {
	return s.MenuRepo.GetByID(ctx, id)
}

func (s *Service) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.Item, int64, error) {
	return s.MenuRepo.GetAll(ctx, req)
}

func (s *Service) GetActiveMenus(ctx context.Context) ([]domainmenu.Item, error) {
	return s.MenuRepo.GetActiveMenus(ctx)
}

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
		parentID, err := s.validParent(ctx, menu.ID, *req.ParentID)
		if err != nil {
			return domainmenu.Item{}, err
		}
		menu.ParentID = parentID
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

// validParent resolves a requested parent_id: empty clears it; otherwise it must
// be a UUID of an existing item other than the item itself, and walking up from
// it must never reach the item (that would be a loop).
func (s *Service) validParent(ctx context.Context, id, parentID string) (*string, error) {
	parentID = strings.TrimSpace(parentID)
	if parentID == "" {
		return nil, nil
	}
	if _, err := uuid.Parse(parentID); err != nil {
		return nil, fmt.Errorf("%w: parent_id must be a UUID", domainmenu.ErrInvalidParent)
	}
	if parentID == id {
		return nil, fmt.Errorf("%w: an item cannot be its own parent", domainmenu.ErrInvalidParent)
	}
	visited := map[string]struct{}{}
	for current := parentID; current != ""; {
		if current == id {
			return nil, fmt.Errorf("%w: that parent would create a loop", domainmenu.ErrInvalidParent)
		}
		if _, seen := visited[current]; seen {
			return nil, fmt.Errorf("%w: the existing tree already loops", domainmenu.ErrInvalidParent)
		}
		visited[current] = struct{}{}
		item, err := s.MenuRepo.GetByID(ctx, current)
		if errors.Is(err, domainmenu.ErrNotFound) {
			return nil, fmt.Errorf("%w: parent does not exist", domainmenu.ErrInvalidParent)
		}
		if err != nil {
			return nil, err
		}
		current = ""
		if item.ParentID != nil {
			current = *item.ParentID
		}
	}
	return &parentID, nil
}
