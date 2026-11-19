package appconfig

import (
	"context"
	"errors"
	"time"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

// Service implements the appconfig use cases.
type Service struct {
	Repo Repository
}

// NewService creates the appconfig service.
func NewService(repo Repository) *Service {
	return &Service{Repo: repo}
}

// GetAll returns a page of records.
func (s *Service) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainappconfig.AppConfig, int64, error) {
	return s.Repo.GetAll(ctx, req)
}

// GetByID returns one record found by ID.
func (s *Service) GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error) {
	return s.Repo.GetByID(ctx, id)
}

// GetByKey returns one record found by key.
func (s *Service) GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error) {
	return s.Repo.GetByKey(ctx, configKey)
}

// Update updates the record.
func (s *Service) Update(ctx context.Context, id string, req dtoappconfig.UpdateAppConfig) (domainappconfig.AppConfig, error) {
	config, err := s.Repo.GetByID(ctx, id)
	if err != nil {
		return domainappconfig.AppConfig{}, err
	}

	config.Value = serviceshared.CleanText(req.Value)
	if req.IsActive != nil {
		config.IsActive = *req.IsActive
	}
	config.UpdatedAt = new(time.Now())

	if err := s.Repo.Update(ctx, config); err != nil {
		return domainappconfig.AppConfig{}, err
	}

	return config, nil
}

// GetString returns the string.
func (s *Service) GetString(ctx context.Context, configKey string, fallback string) (string, error) {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return parseString(entry.Value, fallback), nil
}

// GetBool returns the bool.
func (s *Service) GetBool(ctx context.Context, configKey string, fallback bool) (bool, error) {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return parseBool(entry.Value, fallback)
}

// GetInt returns the int.
func (s *Service) GetInt(ctx context.Context, configKey string, fallback int) (int, error) {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return parseInt(entry.Value, fallback)
}

// GetDuration returns the duration.
func (s *Service) GetDuration(ctx context.Context, configKey string, fallback time.Duration) (time.Duration, error) {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return parseDuration(entry.Value, fallback)
}

// DecodeJSON implements the decode JSON operation.
func (s *Service) DecodeJSON(ctx context.Context, configKey string, target any) error {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return parseJSON(entry.Value, target)
}

// IsEnabled reports whether is enabled.
func (s *Service) IsEnabled(ctx context.Context, configKey string, fallback bool) (bool, error) {
	return s.GetBool(ctx, configKey, fallback)
}

func (s *Service) getActiveConfigByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, bool, error) {
	entry, err := s.Repo.GetByKey(ctx, configKey)
	if err != nil {
		if errors.Is(err, domainappconfig.ErrNotFound) {
			return domainappconfig.AppConfig{}, false, nil
		}
		return domainappconfig.AppConfig{}, false, err
	}
	if !entry.IsActive {
		return domainappconfig.AppConfig{}, false, nil
	}
	return entry, true, nil
}
