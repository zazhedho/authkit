package appconfig

import (
	"context"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func newDryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	sqlDB, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{
		DryRun:                 true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db
}

func TestAppConfigRepositoryDryRun(t *testing.T) {
	repo := NewRepository(newDryRunDB(t))
	ctx := context.Background()

	if _, err := repo.GetByKey(ctx, "site.name"); err != nil {
		t.Fatalf("get by key: %v", err)
	}
	if _, _, err := repo.GetAll(ctx, dtoappconfig.ListRequest{
		Search:         "site",
		Filters:        map[string]any{"category": "general", "is_active": true},
		OrderBy:        "display_name",
		OrderDirection: "ASC",
		Limit:          10,
	}); err != nil {
		t.Fatalf("get all: %v", err)
	}
}
