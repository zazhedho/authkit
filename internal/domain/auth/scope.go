package auth

import (
	"context"
	"encoding/json"
	"strings"
)

type contextKey string

const scopeContextKey contextKey = "auth_scope"

type Scope struct {
	UserID           string
	Username         string
	Role             string
	Permissions      map[string]struct{}
	IsImpersonated   bool
	OriginalUserID   string
	OriginalUsername string
	OriginalRole     string
}

func New(userID, username, role string, permissions []string) Scope {
	permissionSet := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		key := normalizePermissionKey(permission)
		if key == "" {
			continue
		}
		permissionSet[key] = struct{}{}
	}

	return Scope{
		UserID:      strings.TrimSpace(userID),
		Username:    strings.TrimSpace(username),
		Role:        strings.TrimSpace(role),
		Permissions: permissionSet,
	}
}

func NewFromClaims(claims map[string]any, permissions []string) Scope {
	scope := New(
		interfaceString(claims["user_id"]),
		interfaceString(claims["username"]),
		interfaceString(claims["role"]),
		permissions,
	)

	scope.IsImpersonated = interfaceBool(claims["is_impersonated"])
	scope.OriginalUserID = strings.TrimSpace(interfaceString(claims["original_user_id"]))
	scope.OriginalUsername = strings.TrimSpace(interfaceString(claims["original_username"]))
	scope.OriginalRole = strings.TrimSpace(interfaceString(claims["original_role"]))

	return scope
}

func WithContext(ctx context.Context, scope Scope) context.Context {
	return context.WithValue(ctx, scopeContextKey, scope)
}

// FromContext returns the Scope stored in ctx, or an empty Scope.
func FromContext(ctx context.Context) Scope {
	if ctx == nil {
		return Scope{Permissions: map[string]struct{}{}}
	}

	scope, _ := ctx.Value(scopeContextKey).(Scope)
	if scope.Permissions == nil {
		scope.Permissions = map[string]struct{}{}
	}

	return scope
}

func PermissionKey(resource, action string) string {
	resourcePart := normalizeKey(resource)
	actionPart := normalizeKey(action)
	if resourcePart == "" || actionPart == "" {
		return ""
	}

	return resourcePart + ":" + actionPart
}

func (s Scope) Has(resource, action string) bool {
	if strings.TrimSpace(s.Role) == roleSuperAdmin {
		return true
	}

	_, ok := s.Permissions[PermissionKey(resource, action)]
	return ok
}

func (s Scope) ActorUserID() string {
	if s.IsImpersonated && strings.TrimSpace(s.OriginalUserID) != "" {
		return strings.TrimSpace(s.OriginalUserID)
	}
	return strings.TrimSpace(s.UserID)
}

func (s Scope) ActorRole() string {
	if s.IsImpersonated && strings.TrimSpace(s.OriginalRole) != "" {
		return strings.TrimSpace(s.OriginalRole)
	}
	return strings.TrimSpace(s.Role)
}

func normalizePermissionKey(permission string) string {
	parts := strings.SplitN(strings.TrimSpace(permission), ":", 2)
	if len(parts) != 2 {
		return ""
	}

	return PermissionKey(parts[0], parts[1])
}

// roleSuperAdmin repeats domain/user.RoleSuperAdmin: domain packages never
// import each other, and the value is part of the persisted role contract.
const roleSuperAdmin = "superadmin"

// The helpers below match the gokit conversions Scope used before the domain
// layer became stdlib-only, so claim parsing behaves the same.
func interfaceString(data any) string {
	switch v := data.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		b, _ := json.Marshal(data)
		return string(b)
	}
}

func interfaceBool(data any) bool {
	switch v := data.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		b, _ := json.Marshal(data)
		return strings.EqualFold(strings.Trim(string(b), `"`), "true")
	}
}

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// Actor is the authenticated caller as the services see it. Handlers build it
// from the request Scope, so services never read the request context.
type Actor struct {
	UserID           string
	Username         string
	Role             string
	Permissions      map[string]struct{}
	IsImpersonated   bool
	OriginalUserID   string
	OriginalUsername string
	OriginalRole     string
}

// ActorOf returns the scope's identity for passing into a service. It is a
// function, not a Scope method, because Scope is part of the public API.
func ActorOf(s Scope) Actor {
	return Actor(s)
}

// Has reports whether the actor may perform action on resource; superadmin
// always may.
func (a Actor) Has(resource, action string) bool {
	if strings.TrimSpace(a.Role) == roleSuperAdmin {
		return true
	}

	_, ok := a.Permissions[PermissionKey(resource, action)]
	return ok
}
