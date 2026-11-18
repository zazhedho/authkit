package menu

import (
	"context"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	dtomenu "github.com/zazhedho/authkit/internal/dto/menu"
)

type Service interface {
	GetByID(ctx context.Context, id string) (domainmenu.MenuItem, error)
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.MenuItem, int64, error)
	GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error)
	GetUserMenus(ctx context.Context, userId string) ([]domainmenu.MenuItem, error)
	Update(ctx context.Context, id string, req dtomenu.MenuUpdate) (domainmenu.MenuItem, error)
}
