package authkit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	domainuser "github.com/zazhedho/authkit/domain/user"
	"gorm.io/gorm"
)

func init() { gin.SetMode(gin.TestMode) }

func testConfig(db *gorm.DB) Config {
	return Config{DB: db, AppName: "testapp", JWTKey: testJWTKey}
}

func newTestKit(t *testing.T, mutate func(*Config)) (*Kit, *fakeDriver) {
	t.Helper()
	db, drv := newFakeDB(t)
	cfg := testConfig(db)
	if mutate != nil {
		mutate(&cfg)
	}
	kit, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return kit, drv
}

func tokenFor(t *testing.T, kit *Kit, id, role string) string {
	t.Helper()
	tok, err := kit.Tokens().Generate(&domainuser.Users{Id: id, Name: "User " + id, Email: id + "@example.test", Role: role}, "test-log")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	return tok
}

func do(engine http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	db, _ := newFakeDB(t)

	if _, err := New(Config{AppName: "testapp", JWTKey: testJWTKey}); err == nil {
		t.Fatal("expected error for nil DB")
	}
	short := testConfig(db)
	short.JWTKey = "too-short"
	if _, err := New(short); err == nil {
		t.Fatal("expected error for short JWT key")
	}
	noName := testConfig(db)
	noName.AppName = ""
	if _, err := New(noName); err == nil {
		t.Fatal("expected error for empty AppName")
	}
}

func TestNewWithoutRedisOrMailer(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	if kit.Users() == nil || kit.Audit() == nil || kit.AppConfig() == nil || kit.Tokens() == nil {
		t.Fatal("accessors must be non-nil")
	}
	if kit.Auth() == nil || kit.Can("a", "b") == nil || kit.Role("x") == nil {
		t.Fatal("middleware constructors must be non-nil")
	}
}

func TestNewDoesNotTouchDatabase(t *testing.T) {
	kit, drv := newTestKit(t, nil)
	_ = kit
	drv.mu.Lock()
	defer drv.mu.Unlock()
	if len(drv.queries) != 0 {
		t.Fatalf("New must not query the database, got %v", drv.queries)
	}
}

func TestCanAllowsAndDenies(t *testing.T) {
	kit, drv := newTestKit(t, nil)
	drv.addUser(fakeUser{ID: "u-allowed", Role: "viewer", Permissions: []string{"trips:create"}})
	drv.addUser(fakeUser{ID: "u-denied", Role: "viewer", Permissions: []string{"trips:view"}})
	drv.addUser(fakeUser{ID: "u-super", Role: "superadmin"})

	engine := gin.New()
	group := engine.Group("/x")
	group.Use(kit.Auth(), kit.Can("trips", "create"))
	group.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"with permission", tokenFor(t, kit, "u-allowed", "viewer"), http.StatusOK},
		{"without permission", tokenFor(t, kit, "u-denied", "viewer"), http.StatusForbidden},
		{"superadmin", tokenFor(t, kit, "u-super", "superadmin"), http.StatusOK},
		{"no token", "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(engine, http.MethodGet, "/x/ping", tc.token).Code; got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRoleAllowsAndDenies(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	engine := gin.New()
	group := engine.Group("/x")
	group.Use(kit.Auth(), kit.Role("admin"))
	group.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	if got := do(engine, http.MethodGet, "/x/ping", tokenFor(t, kit, "a", "admin")).Code; got != http.StatusOK {
		t.Fatalf("admin: got %d", got)
	}
	if got := do(engine, http.MethodGet, "/x/ping", tokenFor(t, kit, "v", "viewer")).Code; got != http.StatusForbidden {
		t.Fatalf("viewer: got %d", got)
	}
}

func TestScopeFromReturnsAuthenticatedUser(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	var gotID, gotRole string
	engine := gin.New()
	engine.GET("/who", kit.Auth(), func(c *gin.Context) {
		s := ScopeFrom(c.Request.Context())
		gotID, gotRole = s.UserID, s.Role
		c.Status(http.StatusOK)
	})

	if code := do(engine, http.MethodGet, "/who", tokenFor(t, kit, "user-42", "viewer")).Code; code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	if gotID != "user-42" || gotRole != "viewer" {
		t.Fatalf("scope = %q/%q", gotID, gotRole)
	}
}
