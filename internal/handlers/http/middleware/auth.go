package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Middleware authenticates requests and checks roles and permissions.
type Middleware struct {
	BlacklistRepo   TokenRevocations
	PermissionRepo  PermissionLookup
	PermissionCache PermissionCache
	Tokens          TokenVerifier
	// PermissionCacheTTL is how long cached permission keys live; a
	// non-positive value disables caching.
	PermissionCacheTTL time.Duration

	users      UserStates
	stateCache StateCache
	sessions   SessionIndex
}

// ErrMissingDependency is returned by New when a dependency Auth cannot run
// safely without is nil.
var ErrMissingDependency = errors.New("middleware: a required dependency is nil")

// New builds the middleware. blacklistRepo, permissionRepo, tokens and users
// are required: without users Auth could only trust the token's role claim.
// permissionCache, stateCache and sessions may be nil (no caching, sessions off).
func New(blacklistRepo TokenRevocations,
	permissionRepo PermissionLookup,
	permissionCache PermissionCache,
	tokens TokenVerifier,
	permissionCacheTTL time.Duration,
	users UserStates,
	stateCache StateCache,
	sessions SessionIndex) (*Middleware, error) {
	if blacklistRepo == nil || permissionRepo == nil || tokens == nil || users == nil {
		return nil, ErrMissingDependency
	}
	return &Middleware{
		BlacklistRepo:      blacklistRepo,
		PermissionRepo:     permissionRepo,
		PermissionCache:    permissionCache,
		Tokens:             tokens,
		PermissionCacheTTL: permissionCacheTTL,
		users:              users,
		stateCache:         stateCache,
		sessions:           sessions,
	}, nil
}

// AuthMiddleware requires a valid access token and puts the authenticated scope on the request context.
func (m *Middleware) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			err       error
			logID     uuid.UUID
			logPrefix string
		)

		logID = gokit.RequestID(ctx)
		logPrefix = "[AuthMiddleware]"

		tokenString, dataJWT, err := m.Tokens.ClaimsFromRequest(ctx.Request)
		if err != nil {
			logus.LogContextf(ctx, logus.LevelError, "%s; Invalid token; Error: %s;", logPrefix, err.Error())
			res := gokit.Unauthorized(logID, "Invalid or expired token. Please login again.")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		}
		logPrefix += fmt.Sprintf("[%s][%s]", gokit.InterfaceString(dataJWT["jti"]), gokit.InterfaceString(dataJWT["user_id"]))

		tokenType := strings.TrimSpace(gokit.InterfaceString(dataJWT["token_type"]))
		if tokenType != tokenTypeAccess {
			logus.LogContextf(ctx, logus.LevelError, "%s; Invalid token type used on protected route", logPrefix)
			res := gokit.Unauthorized(logID, "Invalid token type. Please use an access token.")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		}

		isBlacklisted, err := m.BlacklistRepo.ExistsByToken(ctx.Request.Context(), tokenString)
		if err != nil {
			logus.LogContextf(ctx, logus.LevelError, "%s; blacklistRepo.ExistsByToken; Error: %+v", logPrefix, err)
			res := gokit.InternalServerError(logID)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
			return
		}

		if isBlacklisted {
			logus.LogContextf(ctx, logus.LevelError, "%s; Invalid token; Error: token is blacklisted;", logPrefix)
			res := gokit.Unauthorized(logID, "Your session is no longer valid. Please login again.")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
			return
		}

		if !m.checkLiveUser(ctx, logID, logPrefix, tokenString, dataJWT) {
			return
		}

		ctx.Set(httpshared.CtxKeyAuthData, dataJWT)
		ctx.Set("token", tokenString)
		userID := gokit.InterfaceString(dataJWT["user_id"])
		ctx.Set("userId", userID)
		requestContext := httpshared.WithAuthData(ctx.Request.Context(), dataJWT)
		requestContext = logus.WithRequestID(requestContext, logID)
		requestContext = logus.WithUserID(requestContext, userID)
		ctx.Request = ctx.Request.WithContext(domainauth.WithContext(requestContext, domainauth.NewFromClaims(dataJWT, nil)))

		ctx.Next()
	}
}

// checkLiveUser applies the per-user checks: the user still exists, the token
// was issued after tokens_valid_after, the role is the current one and, with
// Redis sessions, the token's session is still alive. An impersonation token is
// held to the same rules for the original user. It writes the 401 or 500
// itself and returns false on failure.
func (m *Middleware) checkLiveUser(ctx *gin.Context, logID uuid.UUID, logPrefix, tokenString string, claims map[string]any) bool {
	reject := func(message string) bool {
		res := gokit.Unauthorized(logID, message)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return false
	}
	fail := func(step string, err error) bool {
		logus.LogContextf(ctx, logus.LevelError, "%s; %s; Error: %+v", logPrefix, step, err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return false
	}

	userID := strings.TrimSpace(gokit.InterfaceString(claims["user_id"]))
	state, err := m.userState(ctx.Request.Context(), userID)
	if errors.Is(err, domainuser.ErrNotFound) {
		logus.LogContextf(ctx, logus.LevelWarn, "%s; token for a user that no longer exists", logPrefix)
		return reject("Invalid or expired token. Please login again.")
	}
	if err != nil {
		return fail("Users.GetAuthState", err)
	}
	if state.TokensValidAfter != nil && domainauth.RevokedBy(claims, *state.TokensValidAfter) {
		return reject("Your session is no longer valid. Please login again.")
	}
	claims["role"] = state.Role

	if httpshared.InterfaceBool(claims["is_impersonated"]) {
		originalID := strings.TrimSpace(gokit.InterfaceString(claims["original_user_id"]))
		if originalID == "" {
			return reject("Invalid or expired token. Please login again.")
		}
		original, err := m.userState(ctx.Request.Context(), originalID)
		if errors.Is(err, domainuser.ErrNotFound) {
			logus.LogContextf(ctx, logus.LevelWarn, "%s; impersonation token of a user that no longer exists", logPrefix)
			return reject("Invalid or expired token. Please login again.")
		}
		if err != nil {
			return fail("Users.GetAuthState(original)", err)
		}
		if original.TokensValidAfter != nil && domainauth.RevokedBy(claims, *original.TokensValidAfter) {
			return reject("Your session is no longer valid. Please login again.")
		}
	}

	if m.sessions != nil && !httpshared.InterfaceBool(claims["no_session"]) {
		live, err := m.sessions.HasAccessTokenSession(ctx.Request.Context(), tokenString)
		if err != nil {
			return fail("Sessions.HasAccessTokenSession", err)
		}
		if !live {
			return reject("Your session is no longer valid. Please login again.")
		}
	}
	return true
}

func (m *Middleware) userState(ctx context.Context, userID string) (domainuser.AuthState, error) {
	if m.stateCache != nil {
		if state, ok := m.stateCache.GetAuthState(ctx, userID); ok {
			return state, nil
		}
	}
	state, err := m.users.GetAuthState(ctx, userID)
	if err != nil {
		return domainuser.AuthState{}, err
	}
	if m.stateCache != nil {
		m.stateCache.SetAuthState(ctx, userID, state, m.PermissionCacheTTL)
	}
	return state, nil
}

func (m *Middleware) RoleMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			logID     uuid.UUID
			logPrefix string
		)

		logID = gokit.RequestID(ctx)
		logPrefix = "[RoleMiddleware]"

		scope := domainauth.FromContext(ctx.Request.Context())
		if strings.TrimSpace(scope.Role) == "" {
			authData, exists := ctx.Get(httpshared.CtxKeyAuthData)
			if !exists {
				logus.LogContextf(ctx, logus.LevelError, "%s; AuthData not found", logPrefix)
				res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
				ctx.AbortWithStatusJSON(http.StatusForbidden, res)
				return
			}

			dataJWT, ok := authData.(map[string]any)
			if !ok {
				logus.LogContextf(ctx, logus.LevelError, "%s; Invalid AuthData type", logPrefix)
				res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
				ctx.AbortWithStatusJSON(http.StatusForbidden, res)
				return
			}

			scope = domainauth.NewFromClaims(dataJWT, nil)
			ctx.Request = ctx.Request.WithContext(domainauth.WithContext(ctx.Request.Context(), scope))
		}

		userRole := strings.TrimSpace(scope.Role)
		if userRole == "" {
			logus.LogContextf(ctx, logus.LevelError, "%s; AuthData not found", logPrefix)
			res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
			ctx.AbortWithStatusJSON(http.StatusForbidden, res)
			return
		}

		if userRole == domainuser.RoleSuperAdmin {
			ctx.Next()
			return
		}

		isAllowed := slices.Contains(allowedRoles, userRole)
		if !isAllowed {
			logus.LogContextf(ctx, logus.LevelError, "%s; User with role '%s' tried to access a restricted route;", logPrefix, userRole)
			res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
			ctx.AbortWithStatusJSON(http.StatusForbidden, res)
			return
		}

		ctx.Next()
	}
}

func (m *Middleware) PermissionMiddleware(resource, action string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			logID     uuid.UUID
			logPrefix string
		)

		logID = gokit.RequestID(ctx)
		logPrefix = "[PermissionMiddleware]"

		scope, ok := m.loadScopePermissions(ctx, logID, logPrefix)
		if !ok {
			return
		}

		targetResource := strings.TrimSpace(resource)
		targetAction := strings.TrimSpace(action)

		// Superadmin bypasses all permission checks (Has is true for it).
		if !scope.Has(targetResource, targetAction) {
			logus.LogContextf(ctx, logus.LevelError, "%s; User '%s' lacks permission '%s:%s'", logPrefix, scope.UserID, targetResource, targetAction)
			res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
			ctx.AbortWithStatusJSON(http.StatusForbidden, res)
			return
		}

		ctx.Next()
	}
}

// LoadPermissionsMiddleware loads the user's permissions into the request
// scope like PermissionMiddleware, but never rejects for lacking one.
func (m *Middleware) LoadPermissionsMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		logID := gokit.RequestID(ctx)

		if _, ok := m.loadScopePermissions(ctx, logID, "[LoadPermissionsMiddleware]"); !ok {
			return
		}

		ctx.Next()
	}
}

// loadScopePermissions is the loading half shared by PermissionMiddleware and
// LoadPermissionsMiddleware. It aborts the request and returns false when the
// permissions cannot be established; superadmin returns without a lookup.
func (m *Middleware) loadScopePermissions(ctx *gin.Context, logID uuid.UUID, logPrefix string) (domainauth.Scope, bool) {
	authData, exists := ctx.Get(httpshared.CtxKeyAuthData)
	if !exists {
		logus.LogContextf(ctx, logus.LevelError, "%s; AuthData not found", logPrefix)
		res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
		ctx.AbortWithStatusJSON(http.StatusForbidden, res)
		return domainauth.Scope{}, false
	}
	dataJWT, ok := authData.(map[string]any)
	if !ok {
		logus.LogContextf(ctx, logus.LevelError, "%s; Invalid AuthData type", logPrefix)
		res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
		ctx.AbortWithStatusJSON(http.StatusForbidden, res)
		return domainauth.Scope{}, false
	}

	userRole := strings.TrimSpace(gokit.InterfaceString(dataJWT["role"]))
	if userRole == "" {
		logus.LogContextf(ctx, logus.LevelError, "%s; there is no role user", logPrefix)
		res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
		ctx.AbortWithStatusJSON(http.StatusForbidden, res)
		return domainauth.Scope{}, false
	}

	if userRole == domainuser.RoleSuperAdmin {
		return domainauth.NewFromClaims(dataJWT, nil), true
	}

	userID := strings.TrimSpace(gokit.InterfaceString(dataJWT["user_id"]))
	if userID == "" {
		logus.LogContextf(ctx, logus.LevelError, "%s; Invalid token claims: user_id is empty", logPrefix)
		res := gokit.Unauthorized(logID, "Invalid or expired token. Please login again.")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, res)
		return domainauth.Scope{}, false
	}

	permissionKeys, err := m.loadPermissionKeys(ctx.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, domainuser.ErrNotFound) {
			logus.LogContextf(ctx, logus.LevelWarn, "%s; User '%s' not found when loading permissions", logPrefix, userID)
			res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
			ctx.AbortWithStatusJSON(http.StatusForbidden, res)
			return domainauth.Scope{}, false
		}

		logus.LogContextf(ctx, logus.LevelError, "%s; Failed to get user permissions: %s", logPrefix, err.Error())
		res := gokit.InternalServerError(logID)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, res)
		return domainauth.Scope{}, false
	}

	dataJWT["permissions"] = permissionKeys
	ctx.Set(httpshared.CtxKeyAuthData, dataJWT)
	ctx.Set("permissions", permissionKeys)

	scope := domainauth.NewFromClaims(dataJWT, permissionKeys)
	ctx.Request = ctx.Request.WithContext(domainauth.WithContext(ctx.Request.Context(), scope))

	return scope, true
}

func (m *Middleware) loadPermissionKeys(ctx context.Context, userID string) ([]string, error) {
	if m.PermissionCache != nil {
		if keys, ok := m.PermissionCache.Get(ctx, userID); ok {
			return keys, nil
		}
	}
	permissions, err := m.PermissionRepo.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	keys := permissionKeysFromPermissions(permissions)
	if m.PermissionCache != nil {
		m.PermissionCache.Set(ctx, userID, keys, m.PermissionCacheTTL)
	}
	return keys, nil
}

func permissionKeysFromPermissions(permissions []domainpermission.Permission) []string {
	permissionKeys := make([]string, 0, len(permissions))
	for _, perm := range permissions {
		permissionKey := domainauth.PermissionKey(perm.Resource, perm.Action)
		if permissionKey != "" {
			permissionKeys = append(permissionKeys, permissionKey)
		}
	}
	return permissionKeys
}
