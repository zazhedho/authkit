package interfacemenu

import (
	"context"
	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	"github.com/zazhedho/authkit/internal/dto"
	"github.com/zazhedho/gokit"
)

type ServiceMenuInterface interface {
	GetByID(ctx context.Context, id string) (domainmenu.MenuItem, error)
	GetAll(ctx context.Context, params gokit.BaseParams) ([]domainmenu.MenuItem, int64, error)
	GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error)
	GetUserMenus(ctx context.Context, userId string) ([]domainmenu.MenuItem, error)
	Update(ctx context.Context, id string, req dto.MenuUpdate) (domainmenu.MenuItem, error)
}
