package middlewares

import (
	"context"
	"errors"
	"github.com/zazhedho/authkit/authutil"
	domainauth "github.com/zazhedho/authkit/domain/auth"
	domainpermission "github.com/zazhedho/authkit/domain/permission"
	domainuser "github.com/zazhedho/authkit/domain/user"
	"github.com/zazhedho/gokit/filter"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	redismock "github.com/go-redis/redismock/v9"
	"gorm.io/gorm"
)

type authRepoTestDouble struct {
	blacklisted bool
	err         error
	stored      domainauth.Blacklist
}

func (m *authRepoTestDouble) Store(ctx context.Context, data domainauth.Blacklist) error {
	m.stored = data
	return nil
}

func (m *authRepoTestDouble) GetByToken(ctx context.Context, token string) (domainauth.Blacklist, error) {
	return domainauth.Blacklist{Token: token}, nil
}

func (m *authRepoTestDouble) ExistsByToken(ctx context.Context, token string) (bool, error) {
	return m.blacklisted, m.err
}
func (m *authRepoTestDouble) DeleteExpired(ctx context.Context, now time.Time) error { return nil }

type permissionRepoTestDouble struct {
	permissions []domainpermission.Permission
	err         error
	calls       int
}

func (m *permissionRepoTestDouble) Store(ctx context.Context, data domainpermission.Permission) error {
	return nil
}
func (m *permissionRepoTestDouble) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoTestDouble) GetAll(ctx context.Context, params filter.BaseParams) ([]domainpermission.Permission, int64, error) {
	return nil, 0, nil
}
func (m *permissionRepoTestDouble) Update(ctx context.Context, data domainpermission.Permission) error {
	return nil
}
func (m *permissionRepoTestDouble) Delete(ctx context.Context, id string) error { return nil }
func (m *permissionRepoTestDouble) SoftDelete(ctx context.Context, id, deletedBy string) error {
	return nil
}
func (m *permissionRepoTestDouble) GetByName(ctx context.Context, name string) (domainpermission.Permission, error) {
	return domainpermission.Permission{}, errors.New("not implemented")
}
func (m *permissionRepoTestDouble) GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error) {
	return nil, nil
}
func (m *permissionRepoTestDouble) GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return append([]domainpermission.Permission{}, m.permissions...), nil
}

func performMiddlewareRequest(token string, handlers ...gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", append(handlers, func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
	})...)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/protected", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	router.ServeHTTP(rec, req)
	return rec
}

func performMiddlewareRequestWithSetup(handlers []gin.HandlerFunc, setup func(*gin.Context)) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	chain := make([]gin.HandlerFunc, 0, len(handlers)+2)
	chain = append(chain, func(ctx *gin.Context) {
		if setup != nil {
			setup(ctx)
		}
		ctx.Next()
	})
	chain = append(chain, handlers...)
	chain = append(chain, func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
	})
	router.GET("/protected", chain...)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/protected", nil)
	router.ServeHTTP(rec, req)
	return rec
}

func testTokens(t *testing.T) *authutil.Tokens {
	t.Helper()
	tokens, err := authutil.NewTokens(authutil.TokenConfig{
		Key:     "test-secret-must-be-at-least-32-bytes",
		AppName: "test-app",
	})
	if err != nil {
		t.Fatalf("failed to build tokens: %v", err)
	}
	return tokens
}

func testToken(t *testing.T, tokenType string, role string) string {
	t.Helper()
	claims := &authutil.AppClaims{TokenType: tokenType}
	token, err := testTokens(t).GenerateWithClaims(&domainuser.Users{
		Id:   "user-1",
		Name: "Jane",
		Role: role,
	}, "log-1", claims)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return token
}

func TestAuthMiddlewareAllowsValidAccessToken(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
	rec := performMiddlewareRequest(testToken(t, "access", authutil.RoleViewer), mdw.AuthMiddleware())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareRejectsNonAccessToken(t *testing.T) {
	for _, tokenType := range []string{authutil.TokenTypeRefresh, authutil.TokenTypePasswordReset} {
		t.Run(tokenType, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
			rec := performMiddlewareRequest(testToken(t, tokenType, authutil.RoleViewer), mdw.AuthMiddleware())

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuthMiddlewareRejectsBlacklistedToken(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{blacklisted: true}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
	rec := performMiddlewareRequest(testToken(t, "access", authutil.RoleViewer), mdw.AuthMiddleware())

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareRejectsInvalidTokenAndBlacklistError(t *testing.T) {
	tests := []struct {
		name string
		repo *authRepoTestDouble
		code int
	}{
		{
			name: "invalid token",
			repo: &authRepoTestDouble{},
			code: http.StatusUnauthorized,
		},
		{
			name: "blacklist error",
			repo: &authRepoTestDouble{err: errors.New("redis down")},
			code: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := "not-a-token"
			if tt.name == "blacklist error" {
				token = testToken(t, "access", authutil.RoleViewer)
			}
			mdw := NewMiddleware(tt.repo, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
			rec := performMiddlewareRequest(token, mdw.AuthMiddleware())
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRoleMiddlewareBranches(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*gin.Context)
		allowed []string
		code    int
	}{
		{
			name: "missing auth data",
			code: http.StatusForbidden,
		},
		{
			name: "invalid auth data",
			setup: func(ctx *gin.Context) {
				ctx.Set(authutil.CtxKeyAuthData, "bad")
			},
			code: http.StatusForbidden,
		},
		{
			name: "empty role",
			setup: func(ctx *gin.Context) {
				ctx.Set(authutil.CtxKeyAuthData, map[string]any{"role": " "})
			},
			code: http.StatusForbidden,
		},
		{
			name: "disallowed role",
			setup: func(ctx *gin.Context) {
				ctx.Set(authutil.CtxKeyAuthData, map[string]any{"role": authutil.RoleViewer})
			},
			allowed: []string{authutil.RoleAdmin},
			code:    http.StatusForbidden,
		},
		{
			name: "allowed role",
			setup: func(ctx *gin.Context) {
				ctx.Set(authutil.CtxKeyAuthData, map[string]any{"role": authutil.RoleAdmin})
			},
			allowed: []string{authutil.RoleAdmin},
			code:    http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
			rec := performMiddlewareRequestWithSetup([]gin.HandlerFunc{mdw.RoleMiddleware(tt.allowed...)}, tt.setup)
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPermissionMiddlewareAllowsOwnedPermission(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{
		permissions: []domainpermission.Permission{{Resource: "users", Action: "list"}},
	}, nil, testTokens(t), 2*time.Minute)

	rec := performMiddlewareRequest(
		testToken(t, "access", authutil.RoleViewer),
		mdw.AuthMiddleware(),
		mdw.PermissionMiddleware("users", "list"),
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPermissionMiddlewareUsesCachedPermissionsWhenAvailable(t *testing.T) {
	client, mock := redismock.NewClientMock()
	repo := &permissionRepoTestDouble{
		permissions: []domainpermission.Permission{{Resource: "users", Action: "delete"}},
	}
	mdw := NewMiddleware(&authRepoTestDouble{}, repo, nil, testTokens(t), 2*time.Minute)
	mdw.PermissionCache = client
	mock.ExpectGet("permission:user:user-1").SetVal(`["users:list"]`)

	rec := performMiddlewareRequest(
		testToken(t, "access", authutil.RoleViewer),
		mdw.AuthMiddleware(),
		mdw.PermissionMiddleware("users", "list"),
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if repo.calls != 0 {
		t.Fatalf("expected permission repo not to be called on cache hit, got %d calls", repo.calls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestPermissionMiddlewareFallsBackAndCachesPermissionsOnCacheMiss(t *testing.T) {
	client, mock := redismock.NewClientMock()
	repo := &permissionRepoTestDouble{
		permissions: []domainpermission.Permission{{Resource: "users", Action: "list"}},
	}
	mdw := NewMiddleware(&authRepoTestDouble{}, repo, nil, testTokens(t), 2*time.Minute)
	mdw.PermissionCache = client
	mock.ExpectGet("permission:user:user-1").RedisNil()
	mock.ExpectSet("permission:user:user-1", `["users:list"]`, 2*time.Minute).SetVal("OK")

	rec := performMiddlewareRequest(
		testToken(t, "access", authutil.RoleViewer),
		mdw.AuthMiddleware(),
		mdw.PermissionMiddleware("users", "list"),
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if repo.calls != 1 {
		t.Fatalf("expected permission repo to be called once on cache miss, got %d calls", repo.calls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestPermissionMiddlewareRejectsMissingPermission(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{
		permissions: []domainpermission.Permission{{Resource: "users", Action: "view"}},
	}, nil, testTokens(t), 2*time.Minute)

	rec := performMiddlewareRequest(
		testToken(t, "access", authutil.RoleViewer),
		mdw.AuthMiddleware(),
		mdw.PermissionMiddleware("users", "delete"),
	)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPermissionMiddlewareBypassesSuperadmin(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
	rec := performMiddlewareRequest(
		testToken(t, "access", authutil.RoleSuperAdmin),
		mdw.AuthMiddleware(),
		mdw.PermissionMiddleware("anything", "delete"),
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPermissionMiddlewareRejectsInvalidAuthData(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*gin.Context)
		code  int
	}{
		{
			name: "missing auth data",
			code: http.StatusForbidden,
		},
		{
			name: "invalid auth data type",
			setup: func(ctx *gin.Context) {
				ctx.Set(authutil.CtxKeyAuthData, "bad")
			},
			code: http.StatusForbidden,
		},
		{
			name: "missing role",
			setup: func(ctx *gin.Context) {
				ctx.Set(authutil.CtxKeyAuthData, map[string]any{"user_id": "user-1"})
			},
			code: http.StatusForbidden,
		},
		{
			name: "missing user id",
			setup: func(ctx *gin.Context) {
				ctx.Set(authutil.CtxKeyAuthData, map[string]any{"role": authutil.RoleViewer})
			},
			code: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
			rec := performMiddlewareRequestWithSetup([]gin.HandlerFunc{mdw.PermissionMiddleware("users", "read")}, tt.setup)
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPermissionMiddlewareHandlesRepositoryErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{name: "record not found", err: gorm.ErrRecordNotFound, code: http.StatusForbidden},
		{name: "unexpected error", err: errors.New("db down"), code: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{err: tt.err}, nil, testTokens(t), 2*time.Minute)
			rec := performMiddlewareRequest(
				testToken(t, "access", authutil.RoleViewer),
				mdw.AuthMiddleware(),
				mdw.PermissionMiddleware("users", "read"),
			)
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}
