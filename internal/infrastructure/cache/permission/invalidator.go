package permission

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// Invalidator is the invalidator.
type Invalidator interface {
	DeleteUser(ctx context.Context, userIDs ...string)
	DeleteAll(ctx context.Context)
}

type redisInvalidator struct {
	client *redis.Client
}

// NewInvalidator creates a new invalidator.
func NewInvalidator(client *redis.Client) Invalidator {
	if client == nil {
		return nil
	}
	return redisInvalidator{client: client}
}

func (i redisInvalidator) DeleteUser(ctx context.Context, userIDs ...string) {
	DeleteUserPermissionKeys(ctx, i.client, userIDs...)
}

func (i redisInvalidator) DeleteAll(ctx context.Context) {
	DeleteAllUserPermissionKeys(ctx, i.client)
}
