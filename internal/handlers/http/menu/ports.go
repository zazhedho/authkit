package menu

import (
	"context"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	dtomenu "github.com/zazhedho/authkit/internal/dto/menu"
	"github.com/zazhedho/gokit"
)

// Service is what the menu handlers call.
type Service interface {
	GetByID(ctx context.Context, id string) (domainmenu.MenuItem, error)
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainmenu.MenuItem, int64, error)
	GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error)
	GetUserMenus(ctx context.Context, userId string) ([]domainmenu.MenuItem, error)
	Update(ctx context.Context, id string, req dtomenu.MenuUpdate) (domainmenu.MenuItem, error)
}
