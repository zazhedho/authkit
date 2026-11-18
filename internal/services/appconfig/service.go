package appconfig

import (
	"context"
	"errors"
	"github.com/zazhedho/authkit/internal/config"
	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
	interfaceappconfig "github.com/zazhedho/authkit/internal/interfaces/appconfig"
	"github.com/zazhedho/gokit"
	"time"

	"gorm.io/gorm"
)

type AppConfigService struct {
	Repo interfaceappconfig.RepoAppConfigInterface
}

func NewAppConfigService(repo interfaceappconfig.RepoAppConfigInterface) *AppConfigService {
	return &AppConfigService{Repo: repo}
}

func (s *AppConfigService) GetAll(ctx context.Context, params gokit.BaseParams) ([]domainappconfig.AppConfig, int64, error) {
	return s.Repo.GetAll(ctx, params)
}

func (s *AppConfigService) GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error) {
	return s.Repo.GetByID(ctx, id)
}

func (s *AppConfigService) GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error) {
	return s.Repo.GetByKey(ctx, configKey)
}

func (s *AppConfigService) Update(ctx context.Context, id string, req dtoappconfig.UpdateAppConfig) (domainappconfig.AppConfig, error) {
	config, err := s.Repo.GetByID(ctx, id)
	if err != nil {
		return domainappconfig.AppConfig{}, err
	}

	config.Value = gokit.StripHTML(req.Value)
	if req.IsActive != nil {
		config.IsActive = *req.IsActive
	}
	config.UpdatedAt = new(time.Now())

	if err := s.Repo.Update(ctx, config); err != nil {
		return domainappconfig.AppConfig{}, err
	}

	return config, nil
}

func (s *AppConfigService) GetString(ctx context.Context, configKey string, fallback string) (string, error) {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return config.String(entry.Value, fallback), nil
}

func (s *AppConfigService) GetBool(ctx context.Context, configKey string, fallback bool) (bool, error) {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return config.Bool(entry.Value, fallback)
}

func (s *AppConfigService) GetInt(ctx context.Context, configKey string, fallback int) (int, error) {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return config.Int(entry.Value, fallback)
}

func (s *AppConfigService) GetDuration(ctx context.Context, configKey string, fallback time.Duration) (time.Duration, error) {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return fallback, err
	}
	if !found {
		return fallback, nil
	}
	return config.Duration(entry.Value, fallback)
}

func (s *AppConfigService) DecodeJSON(ctx context.Context, configKey string, target any) error {
	entry, found, err := s.getActiveConfigByKey(ctx, configKey)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return config.JSON(entry.Value, target)
}

func (s *AppConfigService) IsEnabled(ctx context.Context, configKey string, fallback bool) (bool, error) {
	return s.GetBool(ctx, configKey, fallback)
}

func (s *AppConfigService) getActiveConfigByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, bool, error) {
	entry, err := s.Repo.GetByKey(ctx, configKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return domainappconfig.AppConfig{}, false, nil
		}
		return domainappconfig.AppConfig{}, false, err
	}
	if !entry.IsActive {
		return domainappconfig.AppConfig{}, false, nil
	}
	return entry, true, nil
}

var _ interfaceappconfig.ServiceAppConfigInterface = (*AppConfigService)(nil)
