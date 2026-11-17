package interfaceuser

import (
	"context"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/gokit"
)

type RepoUserInterface interface {
	gokit.CRUDRepository[domainuser.Users]

	GetByEmail(ctx context.Context, email string) (domainuser.Users, error)
	GetByPhone(ctx context.Context, phone string) (domainuser.Users, error)
}
