package middleware

import (
	"context"
	"encoding/json"
	"errors"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtopermission "github.com/zazhedho/authkit/internal/dto/permission"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	cachepermission "github.com/zazhedho/authkit/internal/infrastructure/cache/permission"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	redismock "github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
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
func (m *permissionRepoTestDouble) GetAll(ctx context.Context, req dtopermission.ListRequest) ([]domainpermission.Permission, int64, error) {
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

func testTokens(t *testing.T) *token.Tokens {
	t.Helper()
	tokens, err := token.NewTokens(token.TokenConfig{
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
	claims := &token.AppClaims{TokenType: tokenType}
	token, err := testTokens(t).GenerateWithClaims("user-1", "Jane", role, "log-1", claims)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return token
}

func TestAuthMiddlewareAllowsValidAccessToken(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
	rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer), mdw.AuthMiddleware())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareRejectsNonAccessToken(t *testing.T) {
	for _, tokenType := range []string{token.TokenTypeRefresh, token.TokenTypePasswordReset} {
		t.Run(tokenType, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
			rec := performMiddlewareRequest(testToken(t, tokenType, domainuser.RoleViewer), mdw.AuthMiddleware())

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuthMiddlewareRejectsBlacklistedToken(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{blacklisted: true}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
	rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer), mdw.AuthMiddleware())

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
				token = testToken(t, "access", domainuser.RoleViewer)
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
				ctx.Set(httpshared.CtxKeyAuthData, "bad")
			},
			code: http.StatusForbidden,
		},
		{
			name: "empty role",
			setup: func(ctx *gin.Context) {
				ctx.Set(httpshared.CtxKeyAuthData, map[string]any{"role": " "})
			},
			code: http.StatusForbidden,
		},
		{
			name: "disallowed role",
			setup: func(ctx *gin.Context) {
				ctx.Set(httpshared.CtxKeyAuthData, map[string]any{"role": domainuser.RoleViewer})
			},
			allowed: []string{domainuser.RoleAdmin},
			code:    http.StatusForbidden,
		},
		{
			name: "allowed role",
			setup: func(ctx *gin.Context) {
				ctx.Set(httpshared.CtxKeyAuthData, map[string]any{"role": domainuser.RoleAdmin})
			},
			allowed: []string{domainuser.RoleAdmin},
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
		testToken(t, "access", domainuser.RoleViewer),
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
	mdw.PermissionCache = cachepermission.NewCache(client)
	mock.ExpectGet("permission:user:user-1").SetVal(`["users:list"]`)

	rec := performMiddlewareRequest(
		testToken(t, "access", domainuser.RoleViewer),
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
	mdw.PermissionCache = cachepermission.NewCache(client)
	mock.ExpectGet("permission:user:user-1").RedisNil()
	mock.ExpectSet("permission:user:user-1", `["users:list"]`, 2*time.Minute).SetVal("OK")

	rec := performMiddlewareRequest(
		testToken(t, "access", domainuser.RoleViewer),
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
		testToken(t, "access", domainuser.RoleViewer),
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
		testToken(t, "access", domainuser.RoleSuperAdmin),
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
				ctx.Set(httpshared.CtxKeyAuthData, "bad")
			},
			code: http.StatusForbidden,
		},
		{
			name: "missing role",
			setup: func(ctx *gin.Context) {
				ctx.Set(httpshared.CtxKeyAuthData, map[string]any{"user_id": "user-1"})
			},
			code: http.StatusForbidden,
		},
		{
			name: "missing user id",
			setup: func(ctx *gin.Context) {
				ctx.Set(httpshared.CtxKeyAuthData, map[string]any{"role": domainuser.RoleViewer})
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
		{name: "record not found", err: domainuser.ErrNotFound, code: http.StatusForbidden},
		{name: "unexpected error", err: errors.New("db down"), code: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{err: tt.err}, nil, testTokens(t), 2*time.Minute)
			rec := performMiddlewareRequest(
				testToken(t, "access", domainuser.RoleViewer),
				mdw.AuthMiddleware(),
				mdw.PermissionMiddleware("users", "read"),
			)
			if rec.Code != tt.code {
				t.Fatalf("expected %d, got %d: %s", tt.code, rec.Code, rec.Body.String())
			}
		})
	}
}

func foreignAppToken(t *testing.T, role string) string {
	t.Helper()
	other, err := token.NewTokens(token.TokenConfig{
		Key:     "test-secret-must-be-at-least-32-bytes",
		AppName: "other-app",
	})
	if err != nil {
		t.Fatalf("failed to build tokens: %v", err)
	}
	token, err := other.GenerateWithClaims("user-1", "Jane", role, "log-1", &token.AppClaims{TokenType: token.TokenTypeAccess})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return token
}

// errorBody decodes an error response and drops the per-request log id so two
// responses can be compared for identical shape and message.
func errorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	delete(body, "log_id")
	return body
}

func TestAuthMiddlewareRejectsTokenFromOtherApp(t *testing.T) {
	for _, role := range []string{domainuser.RoleViewer, domainuser.RoleSuperAdmin} {
		t.Run(role, func(t *testing.T) {
			next := false
			mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
			rec := performMiddlewareRequest(foreignAppToken(t, role), mdw.AuthMiddleware(), func(ctx *gin.Context) { next = true })

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
			}
			if next {
				t.Fatal("next handler must not run for a token from another app")
			}

			// The response must not reveal that the issuer/audience was the problem.
			badSig, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "user-1"}).SignedString([]byte("a-different-secret-of-at-least-32-bytes"))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			badRec := performMiddlewareRequest(badSig, mdw.AuthMiddleware())
			if badRec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 for bad signature, got %d", badRec.Code)
			}
			got, want := errorBody(t, rec), errorBody(t, badRec)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("foreign-app response %v differs from bad-signature response %v", got, want)
			}
		})
	}
}

func TestAuthMiddlewareRejectsLegacyTokenWithoutIssuer(t *testing.T) {
	claims := jwt.MapClaims{
		"user_id":    "user-1",
		"username":   "Jane",
		"role":       domainuser.RoleViewer,
		"token_type": token.TokenTypeAccess,
		"jti":        "log-1",
		"exp":        jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iat":        jwt.NewNumericDate(time.Now()),
	}
	legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret-must-be-at-least-32-bytes"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
	rec := performMiddlewareRequest(legacy, mdw.AuthMiddleware())

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func performLoadPermissions(t *testing.T, repo *permissionRepoTestDouble, token string, withAuth bool) (*httptest.ResponseRecorder, domainauth.Scope) {
	t.Helper()
	mdw := NewMiddleware(&authRepoTestDouble{}, repo, nil, testTokens(t), 2*time.Minute)
	var got domainauth.Scope
	handlers := []gin.HandlerFunc{}
	if withAuth {
		handlers = append(handlers, mdw.AuthMiddleware())
	}
	handlers = append(handlers, mdw.LoadPermissionsMiddleware(), func(ctx *gin.Context) {
		got = domainauth.FromContext(ctx.Request.Context())
	})
	rec := performMiddlewareRequest(token, handlers...)
	return rec, got
}

func TestLoadPermissionsFillsScope(t *testing.T) {
	repo := &permissionRepoTestDouble{permissions: []domainpermission.Permission{{Resource: "media", Action: "list_any"}}}
	_, scope := performLoadPermissions(t, repo, testToken(t, "access", domainuser.RoleViewer), true)

	if !scope.Has("media", "list_any") {
		t.Fatal("expected media:list_any to be granted")
	}
	if scope.Has("x", "y") {
		t.Fatal("x:y must not be granted")
	}
}

func TestLoadPermissionsDoesNotReject(t *testing.T) {
	rec, _ := performLoadPermissions(t, &permissionRepoTestDouble{}, testToken(t, "access", domainuser.RoleViewer), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoadPermissionsSuperadmin(t *testing.T) {
	rec, scope := performLoadPermissions(t, &permissionRepoTestDouble{}, testToken(t, "access", domainuser.RoleSuperAdmin), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !scope.Has("any", "thing") {
		t.Fatal("superadmin must pass every Has check")
	}
}

func TestLoadPermissionsUserNotFound(t *testing.T) {
	rec, _ := performLoadPermissions(t, &permissionRepoTestDouble{err: domainuser.ErrNotFound}, testToken(t, "access", domainuser.RoleViewer), true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoadPermissionsRepoError(t *testing.T) {
	rec, _ := performLoadPermissions(t, &permissionRepoTestDouble{err: errors.New("db down")}, testToken(t, "access", domainuser.RoleViewer), true)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoadPermissionsWithoutAuth(t *testing.T) {
	rec, _ := performLoadPermissions(t, &permissionRepoTestDouble{}, "", false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}
