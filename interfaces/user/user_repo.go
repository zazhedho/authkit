package interfaceuser

import (
	"context"
	domainuser "github.com/zazhedho/authkit/domain/user"
	interfacegeneric "github.com/zazhedho/gokit/repository"
)

type RepoUserInterface interface {
	interfacegeneric.GenericRepository[domainuser.Users]

	GetByEmail(ctx context.Context, email string) (domainuser.Users, error)
	GetByPhone(ctx context.Context, phone string) (domainuser.Users, error)
}
