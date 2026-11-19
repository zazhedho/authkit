package permission

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix = "permission:user:"
	scanCount = int64(100)
)

// Key implements the key operation.
func Key(userID string) string {
	return keyPrefix + userID
}

// GetUserPermissionKeys returns the user permission keys.
func GetUserPermissionKeys(ctx context.Context, client *redis.Client, userID string) ([]string, bool) {
	if client == nil {
		return nil, false
	}

	raw, err := client.Get(ctx, Key(userID)).Result()
	if err != nil {
		return nil, false
	}

	var permissionKeys []string
	if err := json.Unmarshal([]byte(raw), &permissionKeys); err != nil {
		return nil, false
	}
	return permissionKeys, true
}

// SetUserPermissionKeys caches keys for ttl; ttl <= 0 means no caching, since
// redis treats 0 as never expiring and would serve stale permissions.
func SetUserPermissionKeys(ctx context.Context, client *redis.Client, userID string, permissionKeys []string, ttl time.Duration) {
	if client == nil || ttl <= 0 {
		return
	}

	raw, err := json.Marshal(permissionKeys)
	if err != nil {
		return
	}
	_ = client.Set(ctx, Key(userID), string(raw), ttl).Err()
}

// DeleteUserPermissionKeys deletes the user permission keys.
func DeleteUserPermissionKeys(ctx context.Context, client *redis.Client, userIDs ...string) {
	if client == nil {
		return
	}

	keys := make([]string, 0, len(userIDs))
	for _, userID := range userIDs {
		userID = strings.TrimSpace(userID)
		if userID == "" {
			continue
		}
		keys = append(keys, Key(userID))
	}
	if len(keys) == 0 {
		return
	}

	_ = client.Del(ctx, keys...).Err()
}

// DeleteAllUserPermissionKeys deletes the all user permission keys.
func DeleteAllUserPermissionKeys(ctx context.Context, client *redis.Client) {
	if client == nil {
		return
	}

	var cursor uint64
	for {
		keys, nextCursor, err := client.Scan(ctx, cursor, keyPrefix+"*", scanCount).Result()
		if err != nil {
			return
		}
		if len(keys) > 0 {
			_ = client.Del(ctx, keys...).Err()
		}
		if nextCursor == 0 {
			return
		}
		cursor = nextCursor
	}
}

// Cache is the Redis-backed store of a user's permission keys. A Cache built
// from a nil client never hits and ignores writes.
type Cache struct {
	client *redis.Client
}

// NewCache creates a new cache.
func NewCache(client *redis.Client) *Cache {
	return &Cache{client: client}
}

// Get returns the record.
func (c *Cache) Get(ctx context.Context, userID string) ([]string, bool) {
	if c == nil {
		return nil, false
	}
	return GetUserPermissionKeys(ctx, c.client, userID)
}

// Set caches keys for ttl; a non-positive ttl disables caching.
func (c *Cache) Set(ctx context.Context, userID string, keys []string, ttl time.Duration) {
	if c == nil {
		return
	}
	SetUserPermissionKeys(ctx, c.client, userID, keys, ttl)
}
