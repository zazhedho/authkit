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

// Service implements the permission use cases.
type Service struct {
	PermissionRepo  Repository
	PermissionCache Cache
	// NewID makes record ids; nil uses a UUID v7.
	NewID func() string
}

// NewService creates the permission service.
func NewService(permissionRepo Repository, invalidators ...Cache) *Service {
	service := &Service{
		PermissionRepo: permissionRepo,
		NewID:          serviceshared.NewID,
	}
	if len(invalidators) > 0 {
		service.PermissionCache = invalidators[0]
	}
	return service
}

// Create creates the record.
func (s *Service) Create(ctx context.Context, req dtopermission.Create) (domainpermission.Permission, error) {
	existing, _ := s.PermissionRepo.GetByName(ctx, req.Name)
	if existing.ID != "" {
		return domainpermission.Permission{}, errors.New("permission with this name already exists")
	}

	data := domainpermission.Permission{
		ID:          s.newID(),
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

// GetByID returns one record found by ID.
func (s *Service) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	return s.PermissionRepo.GetByID(ctx, id)
}

// GetAll returns a page of records.
func (s *Service) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainpermission.Permission, int64, error) {
	return s.PermissionRepo.GetAll(ctx, req)
}

// GetByResource returns one record found by resource.
func (s *Service) GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error) {
	return s.PermissionRepo.GetByResource(ctx, resource)
}

// GetUserPermissions returns the user permissions.
func (s *Service) GetUserPermissions(ctx context.Context, userID string) ([]domainpermission.Permission, error) {
	return s.PermissionRepo.GetUserPermissions(ctx, userID)
}

// Update updates the record.
func (s *Service) Update(ctx context.Context, id string, req dtopermission.Update) (domainpermission.Permission, error) {
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

// Delete deletes the record.
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
