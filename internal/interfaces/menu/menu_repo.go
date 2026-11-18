package menu

import (
	"context"
	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	"github.com/zazhedho/gokit"
)

type RepoMenuInterface interface {
	gokit.CRUDRepository[domainmenu.MenuItem]

	GetByName(ctx context.Context, name string) (domainmenu.MenuItem, error)
	GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error)
	GetUserMenus(ctx context.Context, userId string) ([]domainmenu.MenuItem, error)
}
