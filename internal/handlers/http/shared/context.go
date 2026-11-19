package shared

import (
	"context"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
)

// CtxKeyAuthData is the ctx key auth data constant.
const CtxKeyAuthData = "auth_data"

type authDataContextKey struct{}

// Get method shapes of gin-style contexts. Older gin versions use string keys;
// gin v1.11 and later use any-typed keys.
type (
	stringKeyGetter interface{ Get(key string) (any, bool) }
	anyKeyGetter    interface{ Get(key any) (any, bool) }
)

// WithAuthData returns a copy of ctx carrying the auth data.
func WithAuthData(ctx context.Context, data map[string]any) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, authDataContextKey{}, data)
}

// GetAuthData returns the auth data.
func GetAuthData(ctx context.Context) map[string]any {
	jwtClaims, _ := contextValue(ctx, CtxKeyAuthData)
	if data, ok := jwtClaims.(map[string]any); ok {
		return data
	}
	return nil
}

func contextValue(ctx context.Context, key string) (any, bool) {
	if ctx == nil {
		return nil, false
	}

	if key == CtxKeyAuthData {
		if value := ctx.Value(authDataContextKey{}); value != nil {
			return value, true
		}
	}

	switch getter := ctx.(type) {
	case stringKeyGetter:
		if value, exists := getter.Get(key); exists {
			return value, true
		}
	case anyKeyGetter:
		if value, exists := getter.Get(key); exists {
			return value, true
		}
	}
	value := ctx.Value(key) //nolint:staticcheck // plain string key kept for backward compatibility
	return value, value != nil
}

// ActorFrom returns the authenticated caller the services take as an explicit
// argument, read from the scope the auth middleware put on ctx.
func ActorFrom(ctx context.Context) domainauth.Actor {
	return domainauth.ActorOf(domainauth.FromContext(ctx))
}
