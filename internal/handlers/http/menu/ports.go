package menu

import (
	"context"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	dtomenu "github.com/zazhedho/authkit/internal/dto/menu"
)

type Service interface {
	GetByID(ctx context.Context, id string) (domainmenu.Item, error)
	GetAll(ctx context.Context, req dtoshared.ListRequest) ([]domainmenu.Item, int64, error)
	GetActiveMenus(ctx context.Context) ([]domainmenu.Item, error)
	GetUserMenus(ctx context.Context, userID string) ([]domainmenu.Item, error)
	Update(ctx context.Context, id string, req dtomenu.Update) (domainmenu.Item, error)
}
