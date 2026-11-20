package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/gokit"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	"github.com/zazhedho/authkit/internal/handlers/http/middleware"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	httpuser "github.com/zazhedho/authkit/internal/handlers/http/user"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	repositorysession "github.com/zazhedho/authkit/internal/repositories/session"
	servicesession "github.com/zazhedho/authkit/internal/services/session"
	serviceuser "github.com/zazhedho/authkit/internal/services/user"
	"github.com/zazhedho/authkit/internal/testutil"
)

// The end-to-end tests below run the real handler, services, middleware and
// session repository (on miniredis) against an in-memory user table.

type memUsers struct {
	mu    sync.Mutex
	byID  map[string]domainuser.Users
	clock func() time.Time
}

func (m *memUsers) get(id string) (domainuser.Users, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	return u, ok
}

func (m *memUsers) Store(_ context.Context, u domainuser.Users) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[u.ID] = u
	return nil
}
func (m *memUsers) GetByID(_ context.Context, id string) (domainuser.Users, error) {
	if u, ok := m.get(id); ok {
		return u, nil
	}
	return domainuser.Users{}, domainuser.ErrNotFound
}
func (m *memUsers) GetAll(context.Context, dtoshared.ListRequest) ([]domainuser.Users, int64, error) {
	return nil, 0, nil
}
func (m *memUsers) GetAllExcludingRole(context.Context, dtoshared.ListRequest, string) ([]domainuser.Users, int64, error) {
	return nil, 0, nil
}
func (m *memUsers) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	return nil
}
func (m *memUsers) GetByEmail(_ context.Context, email string) (domainuser.Users, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.byID {
		if u.Email == email {
			return u, nil
		}
	}
	return domainuser.Users{}, domainuser.ErrNotFound
}
func (m *memUsers) GetByPhone(context.Context, string) (domainuser.Users, error) {
	return domainuser.Users{}, domainuser.ErrNotFound
}
func (m *memUsers) GetByGoogleSubject(context.Context, string) (domainuser.Users, error) {
	return domainuser.Users{}, domainuser.ErrNotFound
}
func (m *memUsers) UpdateFields(_ context.Context, id string, f map[string]any) error {
	_, err := m.write(id, f, false)
	return err
}
func (m *memUsers) UpdateFieldsRevoking(_ context.Context, id string, f map[string]any) (time.Time, error) {
	return m.write(id, f, true)
}
func (m *memUsers) write(id string, f map[string]any, revoke bool) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return time.Time{}, domainuser.ErrNotFound
	}
	if v, ok := f["password"].(string); ok {
		u.Password = v
	}
	var cutoff time.Time
	if revoke {
		cutoff = m.clock()
		u.TokensValidAfter = &cutoff
	}
	m.byID[id] = u
	return cutoff, nil
}
func (m *memUsers) GetAuthState(_ context.Context, id string) (domainuser.AuthState, error) {
	u, ok := m.get(id)
	if !ok {
		return domainuser.AuthState{}, domainuser.ErrNotFound
	}
	return domainuser.AuthState{Role: u.Role, TokensValidAfter: u.TokensValidAfter}, nil
}

type memBlacklist struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (b *memBlacklist) Store(_ context.Context, m domainauth.Blacklist) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	hash := sha256Hex(m.Token)
	if b.seen[hash] {
		return domainauth.ErrDuplicate
	}
	b.seen[hash] = true
	return nil
}
func (b *memBlacklist) ExistsByToken(ctx context.Context, tok string) (bool, error) {
	return b.ExistsByTokenHash(ctx, sha256Hex(tok))
}
func (b *memBlacklist) ExistsByTokenHash(_ context.Context, hash string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seen[hash], nil
}

type noRoles struct{}

func (noRoles) GetByName(context.Context, string) (domainrole.Role, error) {
	return domainrole.Role{ID: "r", Name: "viewer"}, nil
}

type noPermissions struct{}

func (noPermissions) GetUserPermissions(context.Context, string) ([]domainpermission.Permission, error) {
	return nil, nil
}
func (noPermissions) GetByRoleName(context.Context, string) ([]domainpermission.Permission, error) {
	return nil, nil
}

type discardAudit struct{}

func (discardAudit) Store(context.Context, domainaudit.AuditEvent) error { return nil }
func (discardAudit) GetAll(context.Context, gokit.BaseParams) ([]dtoaudit.AuditTrailResponse, int64, error) {
	return nil, 0, nil
}
func (discardAudit) GetByID(context.Context, string) (dtoaudit.AuditTrailResponse, error) {
	return dtoaudit.AuditTrailResponse{}, nil
}

type e2e struct {
	engine   *gin.Engine
	users    *memUsers
	mr       *miniredis.Miniredis
	adminID  string
	targetID string
}

func newE2E(t *testing.T, withRedis bool) *e2e {
	t.Helper()
	tokens, err := token.New(token.Config{Key: testJWTKey, AppName: "e2e", AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	h := &e2e{adminID: uuid.NewString(), targetID: uuid.NewString()}
	h.users = &memUsers{byID: map[string]domainuser.Users{}, clock: time.Now}
	hash := testutil.MustHash(t, "Passw0rd!x")
	for _, u := range []domainuser.Users{
		{ID: h.adminID, Name: "Admin", Email: "admin@x.io", Role: domainuser.RoleSuperAdmin, Password: hash},
		{ID: h.targetID, Name: "Target", Email: "target@x.io", Role: domainuser.RoleViewer, Password: hash},
	} {
		h.users.byID[u.ID] = u
	}
	blacklist := &memBlacklist{seen: map[string]bool{}}

	var (
		sessionSvc httpuser.SessionService
		revoker    serviceuser.SessionRevoker
		index      middleware.SessionIndex
	)
	if withRedis {
		var client *redis.Client
		h.mr = miniredis.RunT(t)
		client = redis.NewClient(&redis.Options{Addr: h.mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })
		repo := repositorysession.NewRepository(client)
		svc := servicesession.NewService(repo, time.Hour)
		sessionSvc, revoker, index = svc, svc, repo
	}
	userSvc := serviceuser.NewService(h.users, blacklist, noRoles{}, noPermissions{}, serviceuser.Options{Tokens: tokens, Sessions: revoker})
	handler := httpuser.New(userSvc, sessionSvc, nil, discardAudit{}, httpuser.Options{
		Tokens: tokens,
		Settings: httpuser.Settings{
			AccessTTL: 15 * time.Minute, RefreshTTL: time.Hour, SessionMaxLifetime: 24 * time.Hour,
		},
	})
	mdw, err := middleware.New(blacklist, noPermissions{}, nil, tokens, time.Minute, h.users, nil, index)
	if err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	h.engine = gin.New()
	h.engine.POST("/login", handler.Login)
	h.engine.POST("/refresh", handler.RefreshToken)
	auth := h.engine.Group("/", mdw.AuthMiddleware())
	auth.GET("/me", func(c *gin.Context) {
		s := domainauth.FromContext(c.Request.Context())
		c.JSON(http.StatusOK, gin.H{"id": s.UserID, "impersonated": s.IsImpersonated})
	})
	auth.POST("/logout", handler.Logout)
	auth.POST("/password", handler.ChangePassword)
	auth.POST("/impersonate/:id", handler.ImpersonateUser)
	auth.POST("/stop", handler.StopImpersonation)
	_ = httpshared.CtxKeyAuthData
	return h
}

type tokens struct{ Access, Refresh string }

func (h *e2e) call(method, path, bearer, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func pair(t *testing.T, code int, body map[string]any) tokens {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	data, _ := body["data"].(map[string]any)
	a, _ := data["access_token"].(string)
	r, _ := data["refresh_token"].(string)
	return tokens{a, r}
}

func (h *e2e) login(t *testing.T, email string) tokens {
	t.Helper()
	code, body := h.call(http.MethodPost, "/login", "", `{"identifier":"`+email+`","password":"Passw0rd!x"}`)
	return pair(t, code, body)
}

func (h *e2e) refresh(refresh string) int {
	code, _ := h.call(http.MethodPost, "/refresh", "", `{"refresh_token":"`+refresh+`"}`)
	return code
}

func (h *e2e) me(access string) int {
	code, _ := h.call(http.MethodGet, "/me", access, "")
	return code
}

func (h *e2e) sessionKeys() int {
	if h.mr == nil {
		return 0
	}
	n := 0
	for _, k := range h.mr.Keys() {
		if strings.HasPrefix(k, "session:") {
			n++
		}
	}
	return n
}

// A replayed rotated refresh token revokes the whole session: the session is
// gone and every token of that login is rejected.
func TestReplayOfARotatedRefreshTokenRevokesTheSession(t *testing.T) {
	h := newE2E(t, true)
	first := h.login(t, "target@x.io")

	code, body := h.call(http.MethodPost, "/refresh", "", `{"refresh_token":"`+first.Refresh+`"}`)
	second := pair(t, code, body)
	if h.me(second.Access) != http.StatusOK {
		t.Fatal("the rotated access token must work")
	}
	if h.sessionKeys() != 1 {
		t.Fatalf("sessions before the replay = %d, want 1", h.sessionKeys())
	}

	if got := h.refresh(first.Refresh); got != http.StatusUnauthorized {
		t.Fatalf("replay: status %d, want 401", got)
	}
	if h.sessionKeys() != 0 {
		t.Fatal("the replay must have deleted the session")
	}
	for name, access := range map[string]string{"first access": first.Access, "second access": second.Access} {
		if got := h.me(access); got != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, got)
		}
	}
	if got := h.refresh(second.Refresh); got != http.StatusUnauthorized {
		t.Errorf("the rotated refresh token must be dead too, got %d", got)
	}
}

// Without sessions the blacklist claims each refresh token once.
func TestRefreshWithoutSessionsClaimsEachTokenOnce(t *testing.T) {
	h := newE2E(t, false)
	first := h.login(t, "target@x.io")
	if got := h.refresh(first.Refresh); got != http.StatusOK {
		t.Fatalf("first refresh: %d", got)
	}
	if got := h.refresh(first.Refresh); got != http.StatusUnauthorized {
		t.Fatalf("replay: %d, want 401", got)
	}
}

func TestStopImpersonationReturnsAUsableTokenWithAndWithoutRedis(t *testing.T) {
	for name, withRedis := range map[string]bool{"redis on": true, "redis off": false} {
		t.Run(name, func(t *testing.T) {
			h := newE2E(t, withRedis)
			admin := h.login(t, "admin@x.io")

			code, body := h.call(http.MethodPost, "/impersonate/"+h.targetID, admin.Access, `{"reason":"support case"}`)
			imp := pair(t, code, body)
			if h.me(imp.Access) != http.StatusOK {
				t.Fatal("the impersonation token must work")
			}

			code, body = h.call(http.MethodPost, "/stop", imp.Access, "")
			restored := pair(t, code, body)
			if got := h.me(restored.Access); got != http.StatusOK {
				t.Fatalf("the restored token must pass Auth, got %d", got)
			}
			if _, who := h.call(http.MethodGet, "/me", restored.Access, ""); who["id"] != h.adminID {
				t.Fatalf("restored identity = %v", who)
			}
		})
	}
}

func TestImpersonationTokenDiesWhenTheAdminIsDeletedOrRevoked(t *testing.T) {
	h := newE2E(t, false)
	admin := h.login(t, "admin@x.io")
	code, body := h.call(http.MethodPost, "/impersonate/"+h.targetID, admin.Access, `{"reason":"support case"}`)
	imp := pair(t, code, body)

	cutoff := time.Now().Add(time.Millisecond)
	a := h.users.byID[h.adminID]
	a.TokensValidAfter = &cutoff
	h.users.byID[h.adminID] = a
	if got := h.me(imp.Access); got != http.StatusUnauthorized {
		t.Fatalf("after the admin's tokens were revoked: %d, want 401", got)
	}
	if code, _ := h.call(http.MethodPost, "/stop", imp.Access, ""); code != http.StatusUnauthorized {
		t.Fatalf("stop after revocation: %d, want 401", code)
	}

	delete(h.users.byID, h.adminID)
	if got := h.me(imp.Access); got != http.StatusUnauthorized {
		t.Fatalf("after the admin was deleted: %d, want 401", got)
	}
}

func TestChangePasswordKeepsOnlyTheCallersSession(t *testing.T) {
	for name, withRedis := range map[string]bool{"redis on": true, "redis off": false} {
		t.Run(name, func(t *testing.T) {
			h := newE2E(t, withRedis)
			// Freeze the cut-off clock behind the token clock to prove the
			// re-issued token is accepted whatever the skew.
			h.users.clock = func() time.Time { return time.Now().Add(2 * time.Second) }
			caller := h.login(t, "target@x.io")
			other := h.login(t, "target@x.io")

			code, body := h.call(http.MethodPost, "/password", caller.Access, `{"current_password":"Passw0rd!x","new_password":"NewPassw0rd!y"}`)
			fresh := pair(t, code, body)
			if data, _ := body["data"].(map[string]any); data["user"] == nil {
				t.Fatalf("the response must carry the user DTO: %v", body)
			}

			if got := h.me(fresh.Access); got != http.StatusOK {
				t.Fatalf("the re-issued access token: %d, want 200", got)
			}
			if got := h.me(caller.Access); got != http.StatusUnauthorized {
				t.Fatalf("the old access token: %d, want 401", got)
			}
			if got := h.me(other.Access); got != http.StatusUnauthorized {
				t.Fatalf("another session's token: %d, want 401", got)
			}
			if got := h.refresh(fresh.Refresh); got != http.StatusOK {
				t.Fatalf("the re-issued refresh token: %d, want 200", got)
			}
			if withRedis && h.sessionKeys() != 1 {
				t.Fatalf("sessions = %d, want only the caller's", h.sessionKeys())
			}
		})
	}
}

var _ = errors.New

// Ending the actor's login (logout, or with Redis a revoked session) ends the
// impersonation started from it, with Redis on and off.
func TestImpersonationEndsWithTheActorsLogin(t *testing.T) {
	for name, withRedis := range map[string]bool{"redis on": true, "redis off": false} {
		t.Run(name+"/logout", func(t *testing.T) {
			h := newE2E(t, withRedis)
			admin := h.login(t, "admin@x.io")
			code, body := h.call(http.MethodPost, "/impersonate/"+h.targetID, admin.Access, `{"reason":"support case"}`)
			imp := pair(t, code, body)
			if got := h.me(imp.Access); got != http.StatusOK {
				t.Fatalf("before logout: %d", got)
			}
			if code, _ := h.call(http.MethodPost, "/logout", admin.Access, ""); code != http.StatusOK {
				t.Fatalf("logout: %d", code)
			}
			if got := h.me(imp.Access); got != http.StatusUnauthorized {
				t.Fatalf("after the actor logged out: %d, want 401", got)
			}
			if code, _ := h.call(http.MethodPost, "/stop", imp.Access, ""); code != http.StatusUnauthorized {
				t.Fatalf("stop after logout: %d, want 401", code)
			}
		})
	}
	t.Run("redis on/session revoked without logout", func(t *testing.T) {
		h := newE2E(t, true)
		admin := h.login(t, "admin@x.io")
		code, body := h.call(http.MethodPost, "/impersonate/"+h.targetID, admin.Access, `{"reason":"support case"}`)
		imp := pair(t, code, body)
		for _, k := range h.mr.Keys() {
			if strings.HasPrefix(k, "session:") {
				h.mr.Del(k) // the session record goes, the impersonation token's own bindings stay
			}
		}
		if got := h.me(imp.Access); got != http.StatusUnauthorized {
			t.Fatalf("after the actor's session was revoked: %d, want 401", got)
		}
	})
}
