package permission

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/logus"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

// The key prefixes carry a version so a change of the stored shape never reads
// an old entry.
const (
	keyPrefix      = "permission:v2:user:"
	stateKeyPrefix = "authstate:v2:user:"
	scanCount      = int64(100)
)

func Key(userID string) string {
	return keyPrefix + userID
}

// StateKey is the cache key of a user's auth state.
func StateKey(userID string) string {
	return stateKeyPrefix + userID
}

func GetUserPermissionKeys(ctx context.Context, client redis.UniversalClient, userID string) ([]string, bool) {
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
func SetUserPermissionKeys(ctx context.Context, client redis.UniversalClient, userID string, permissionKeys []string, ttl time.Duration) {
	if client == nil || ttl <= 0 {
		return
	}

	raw, err := json.Marshal(permissionKeys)
	if err != nil {
		return
	}
	_ = client.Set(ctx, Key(userID), string(raw), ttl).Err()
}

func DeleteUserPermissionKeys(ctx context.Context, client redis.UniversalClient, userIDs ...string) {
	if client == nil {
		return
	}

	keys := make([]string, 0, len(userIDs))
	for _, userID := range userIDs {
		userID = strings.TrimSpace(userID)
		if userID == "" {
			continue
		}
		keys = append(keys, Key(userID), StateKey(userID))
	}
	if len(keys) == 0 {
		return
	}

	if err := client.Del(ctx, keys...).Err(); err != nil {
		logus.LogContextf(ctx, logus.LevelError, "permission cache: delete user keys: %v", err)
	}
}

// DeleteAllUserPermissionKeys deletes every cached permission set; auth states
// are per user and survive.
func DeleteAllUserPermissionKeys(ctx context.Context, client redis.UniversalClient) {
	if client == nil {
		return
	}

	var cursor uint64
	for {
		keys, nextCursor, err := client.Scan(ctx, cursor, keyPrefix+"*", scanCount).Result()
		if err != nil {
			logus.LogContextf(ctx, logus.LevelError, "permission cache: scan: %v", err)
			return
		}
		if len(keys) > 0 {
			if err := client.Del(ctx, keys...).Err(); err != nil {
				logus.LogContextf(ctx, logus.LevelError, "permission cache: delete: %v", err)
			}
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
	client redis.UniversalClient
}

func New(client redis.UniversalClient) *Cache {
	return &Cache{client: client}
}

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

// authState is the cached form of domainuser.AuthState.
type authState struct {
	Role             string     `json:"role"`
	TokensValidAfter *time.Time `json:"tokens_valid_after,omitempty"`
}

func (c *Cache) GetAuthState(ctx context.Context, userID string) (domainuser.AuthState, bool) {
	if c == nil || c.client == nil {
		return domainuser.AuthState{}, false
	}
	raw, err := c.client.Get(ctx, StateKey(userID)).Result()
	if err != nil {
		return domainuser.AuthState{}, false
	}
	var cached authState
	if err := json.Unmarshal([]byte(raw), &cached); err != nil {
		return domainuser.AuthState{}, false
	}
	return domainuser.AuthState(cached), true
}

// SetAuthState caches a state for ttl; a non-positive ttl disables caching.
func (c *Cache) SetAuthState(ctx context.Context, userID string, state domainuser.AuthState, ttl time.Duration) {
	if c == nil || c.client == nil || ttl <= 0 {
		return
	}
	raw, err := json.Marshal(authState(state))
	if err != nil {
		return
	}
	if err := c.client.Set(ctx, StateKey(userID), raw, ttl).Err(); err != nil {
		logus.LogContextf(ctx, logus.LevelError, "permission cache: set auth state: %v", err)
	}
}
