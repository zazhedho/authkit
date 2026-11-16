package interfacemenu

import (
	"context"
	domainmenu "github.com/zazhedho/authkit/domain/menu"
	interfacegeneric "github.com/zazhedho/gokit/repository"
)

type RepoMenuInterface interface {
	interfacegeneric.GenericRepository[domainmenu.MenuItem]

	GetByName(ctx context.Context, name string) (domainmenu.MenuItem, error)
	GetActiveMenus(ctx context.Context) ([]domainmenu.MenuItem, error)
	GetUserMenus(ctx context.Context, userId string) ([]domainmenu.MenuItem, error)
}
