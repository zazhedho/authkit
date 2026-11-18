package permission

import (
	"context"
	"errors"
	"time"

	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	dtopermission "github.com/zazhedho/authkit/internal/dto/permission"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

type Service struct {
	PermissionRepo  Repository
	PermissionCache PermissionCache
	// NewID makes record ids; nil uses a UUID v7.
	NewID func() string
}

func NewService(permissionRepo Repository, invalidators ...PermissionCache) *Service {
	service := &Service{
		PermissionRepo: permissionRepo,
		NewID:          serviceshared.NewID,
	}
	if len(invalidators) > 0 {
		service.PermissionCache = invalidators[0]
	}
	return service
}

func (s *Service) Create(ctx context.Context, req dtopermission.PermissionCreate) (domainpermission.Permission, error) {
	existing, _ := s.PermissionRepo.GetByName(ctx, req.Name)
	if existing.Id != "" {
		return domainpermission.Permission{}, errors.New("permission with this name already exists")
	}

	data := domainpermission.Permission{
		Id:          s.newID(),
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Resource:    req.Resource,
		Action:      req.Action,
		CreatedAt:   time.Now(),
	}

	if err := s.PermissionRepo.Store(ctx, data); err != nil {
		return domainpermission.Permission{}, err
	}
	s.invalidatePermissionCache(ctx)

	return data, nil
}

func (s *Service) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	return s.PermissionRepo.GetByID(ctx, id)
}

func (s *Service) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainpermission.Permission, int64, error) {
	return s.PermissionRepo.GetAll(ctx, req)
}

func (s *Service) GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error) {
	return s.PermissionRepo.GetByResource(ctx, resource)
}

func (s *Service) GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error) {
	return s.PermissionRepo.GetUserPermissions(ctx, userId)
}

func (s *Service) Update(ctx context.Context, id string, req dtopermission.PermissionUpdate) (domainpermission.Permission, error) {
	permission, err := s.PermissionRepo.GetByID(ctx, id)
	if err != nil {
		return domainpermission.Permission{}, err
	}

	if req.DisplayName != "" {
		permission.DisplayName = req.DisplayName
	}
	permission.Description = req.Description
	if req.Resource != "" {
		permission.Resource = req.Resource
	}
	if req.Action != "" {
		permission.Action = req.Action
	}
	permission.UpdatedAt = new(time.Now())

	if err := s.PermissionRepo.Update(ctx, permission); err != nil {
		return domainpermission.Permission{}, err
	}
	s.invalidatePermissionCache(ctx)

	return permission, nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.PermissionRepo.Delete(ctx, id); err != nil {
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

func (s *Service) newID() string {
	if s.NewID != nil {
		return s.NewID()
	}
	return serviceshared.NewID()
}
