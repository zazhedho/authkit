package router

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/zazhedho/authkit/internal/config"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	"github.com/zazhedho/authkit/internal/testutil"
)

var baseRoutes = []string{ // "METHOD path", relative to the "/api" group
	"GET /api/user/register/status", "POST /api/user/register", "POST /api/user/register/otp/send",
	"POST /api/user/login", "POST /api/user/google/login", "POST /api/user/refresh-token",
	"POST /api/user/forgot-password", "POST /api/user/reset-password", "POST /api/user/logout",
	"GET /api/user", "GET /api/user/:id", "POST /api/user/:id/impersonate",
	"POST /api/user/stop-impersonation", "PUT /api/user", "PUT /api/user/:id",
	"PUT /api/user/change/password", "DELETE /api/user", "DELETE /api/user/:id", "POST /api/user",
	"GET /api/users",
	"GET /api/roles", "POST /api/role", "GET /api/role/:id", "PUT /api/role/:id",
	"DELETE /api/role/:id", "POST /api/role/:id/permissions",
	"GET /api/permissions", "GET /api/permissions/me", "POST /api/permission",
	"GET /api/permission/:id", "PUT /api/permission/:id", "DELETE /api/permission/:id",
	"GET /api/menus/active", "GET /api/menus/me", "GET /api/menus", "GET /api/menu/:id", "PUT /api/menu/:id",
	"GET /api/configs", "GET /api/config/:id", "PUT /api/config/:id",
	"GET /api/audits", "GET /api/audit/:id",
} // 42 routes

var sessionRoutes = []string{
	"GET /api/user/sessions", "DELETE /api/user/session/:session_id", "POST /api/user/sessions/revoke-others",
}

func registeredRoutes(engine *gin.Engine) []string {
	got := make([]string, 0, len(engine.Routes()))
	for _, r := range engine.Routes() {
		got = append(got, r.Method+" "+r.Path)
	}
	sort.Strings(got)
	return got
}

func sortedCopy(in ...[]string) []string {
	var out []string
	for _, s := range in {
		out = append(out, s...)
	}
	sort.Strings(out)
	return out
}

func requireSameRoutes(t *testing.T, got, want []string) {
	t.Helper()
	gotSet, wantSet := map[string]bool{}, map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing route %s", w)
		}
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Errorf("unexpected route %s", g)
		}
	}
	if len(got) != len(want) {
		t.Errorf("route count = %d, want %d", len(got), len(want))
	}
}

func init() { gin.SetMode(gin.TestMode) }

const testJWTKey = "test-secret-must-be-at-least-32-bytes"

// newCore wires the module set over the in-memory driver, with the defaults New
// would apply.
func newCore(t *testing.T, mutate func(*config.Config)) (*Core, *testutil.Driver) {
	t.Helper()
	db, drv := testutil.NewDB(t)
	cfg := config.Config{DB: db, AppName: "testapp", JWTKey: testJWTKey}
	if mutate != nil {
		mutate(&cfg)
	}
	cfg = config.WithDefaults(cfg)
	core, err := Wire(cfg)
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	return core, drv
}

func tokenFor(t *testing.T, core *Core, id, role string) string {
	t.Helper()
	tok, err := core.Tokens.GenerateWithClaims(id, "User "+id, role, &token.AppClaims{NoSession: true}, time.Time{})
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

func newMiniRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func mountedEngine(t *testing.T, core *Core) *gin.Engine {
	t.Helper()
	engine := gin.New()
	if err := Mount(engine.Group("/api"), core.Deps); err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestMountRegistersExactlyBaseRoutesWithoutRedis(t *testing.T) {
	core, _ := newCore(t, nil)
	requireSameRoutes(t, registeredRoutes(mountedEngine(t, core)), baseRoutes)
	if len(baseRoutes) != 42 {
		t.Fatalf("baseRoutes has %d entries, want 42", len(baseRoutes))
	}
}

func TestMountRegistersSessionRoutesWithRedis(t *testing.T) {
	_, client := newMiniRedis(t)
	core, _ := newCore(t, func(c *config.Config) { c.Redis = client })
	requireSameRoutes(t, registeredRoutes(mountedEngine(t, core)), sortedCopy(baseRoutes, sessionRoutes))
}

func TestMountRegistersSessionRoutesWithRedisButNoMailer(t *testing.T) {
	// Redis without Mailer still mounts sessions; OTP and reset stay inert.
	_, client := newMiniRedis(t)
	core, _ := newCore(t, func(c *config.Config) { c.Redis = client; c.Mailer = nil })
	requireSameRoutes(t, registeredRoutes(mountedEngine(t, core)), sortedCopy(baseRoutes, sessionRoutes))
}

func TestMountCanServeTwoGroups(t *testing.T) {
	core, _ := newCore(t, nil)
	engine := gin.New()
	if err := Mount(engine.Group("/api"), core.Deps); err != nil {
		t.Fatal(err)
	}
	if err := Mount(engine.Group("/v2"), core.Deps); err != nil {
		t.Fatal(err)
	}

	for _, prefix := range []string{"/api", "/v2"} {
		if code := do(engine, http.MethodGet, prefix+"/user/register/status", "").Code; code != http.StatusOK {
			t.Fatalf("%s register status: got %d", prefix, code)
		}
		if code := do(engine, http.MethodGet, prefix+"/users", "").Code; code != http.StatusUnauthorized {
			t.Fatalf("%s users: got %d", prefix, code)
		}
	}
}

func TestProtectedRouteRequiresToken(t *testing.T) {
	core, _ := newCore(t, nil)
	if code := do(mountedEngine(t, core), http.MethodGet, "/api/users", "").Code; code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", code)
	}
}

func TestPublicRouteNeedsNoToken(t *testing.T) {
	core, _ := newCore(t, nil)
	if code := do(mountedEngine(t, core), http.MethodGet, "/api/user/register/status", "").Code; code != http.StatusOK {
		t.Fatalf("got %d, want 200", code)
	}
}

type routePermission struct {
	method, path string
	resource     string // empty: authentication only
	action       string
	needsRedis   bool
}

// routePermissions lists every authenticated route and the (resource, action)
// permission it must demand.
var routePermissions = []routePermission{
	// user routes
	{method: "POST", path: "/api/user/logout"},
	{method: "GET", path: "/api/user"},
	{method: "GET", path: "/api/user/u-target", resource: "users", action: "view"},
	{method: "POST", path: "/api/user/u-target/impersonate", resource: "users", action: "impersonate"},
	{method: "POST", path: "/api/user/stop-impersonation"},
	{method: "PUT", path: "/api/user"},
	{method: "PUT", path: "/api/user/u-target", resource: "users", action: "update"},
	{method: "PUT", path: "/api/user/change/password"},
	{method: "DELETE", path: "/api/user"},
	{method: "DELETE", path: "/api/user/u-target", resource: "users", action: "delete"},
	{method: "POST", path: "/api/user", resource: "users", action: "create"},
	{method: "GET", path: "/api/users", resource: "users", action: "list"},
	// RoleRoutes
	{method: "GET", path: "/api/roles", resource: "roles", action: "list"},
	{method: "POST", path: "/api/role", resource: "roles", action: "create"},
	{method: "GET", path: "/api/role/r-1", resource: "roles", action: "view"},
	{method: "PUT", path: "/api/role/r-1", resource: "roles", action: "update"},
	{method: "DELETE", path: "/api/role/r-1", resource: "roles", action: "delete"},
	{method: "POST", path: "/api/role/r-1/permissions", resource: "roles", action: "assign_permissions"},
	// PermissionRoutes
	{method: "GET", path: "/api/permissions", resource: "permissions", action: "list"},
	{method: "GET", path: "/api/permissions/me"},
	{method: "POST", path: "/api/permission", resource: "permissions", action: "create"},
	{method: "GET", path: "/api/permission/p-1", resource: "permissions", action: "view"},
	{method: "PUT", path: "/api/permission/p-1", resource: "permissions", action: "update"},
	{method: "DELETE", path: "/api/permission/p-1", resource: "permissions", action: "delete"},
	// MenuRoutes
	{method: "GET", path: "/api/menus/active"},
	{method: "GET", path: "/api/menus/me"},
	{method: "GET", path: "/api/menus", resource: "menus", action: "list"},
	{method: "GET", path: "/api/menu/m-1", resource: "menus", action: "view"},
	{method: "PUT", path: "/api/menu/m-1", resource: "menus", action: "update"},
	// AppConfigRoutes
	{method: "GET", path: "/api/configs", resource: "configs", action: "list"},
	{method: "GET", path: "/api/config/c-1", resource: "configs", action: "view"},
	{method: "PUT", path: "/api/config/c-1", resource: "configs", action: "update"},
	// AuditRoutes
	{method: "GET", path: "/api/audits", resource: "audits", action: "list"},
	{method: "GET", path: "/api/audit/a-1", resource: "audits", action: "view"},
	// SessionRoutes (only mounted with Redis): authentication only
	{method: "GET", path: "/api/user/sessions", needsRedis: true},
	{method: "DELETE", path: "/api/user/session/s-1", needsRedis: true},
	{method: "POST", path: "/api/user/sessions/revoke-others", needsRedis: true},
}

// routeProbe drives requests at a mounted engine as users with chosen permissions.
type routeProbe struct {
	engine *gin.Engine
	core   *Core
	drv    *testutil.Driver
	// all is every distinct permission any route demands.
	all map[string]bool
}

func TestMountAppliesPermissionPerRoute(t *testing.T) {
	_, client := newMiniRedis(t)
	core, drv := newCore(t, func(c *config.Config) { c.Redis = client })
	probe := &routeProbe{engine: mountedEngine(t, core), core: core, drv: drv, all: map[string]bool{}}
	for _, rp := range routePermissions {
		if rp.resource != "" {
			probe.all[rp.resource+":"+rp.action] = true
		}
	}

	for _, rp := range routePermissions {
		name := rp.method + " " + rp.path
		t.Run(name, func(t *testing.T) { probe.check(t, name, rp) })
	}
}

// status calls the route as user id with the given role, or without a token for "".
func (p *routeProbe) status(t *testing.T, rp routePermission, id string) int {
	t.Helper()
	token := ""
	if id != "" {
		token = tokenFor(t, p.core, id, "viewer")
	}
	return do(p.engine, rp.method, rp.path, token).Code
}

func (p *routeProbe) check(t *testing.T, name string, rp routePermission) {
	if code := p.status(t, rp, ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", code)
	}
	suffix := strings.ReplaceAll(name, " ", "_")

	if rp.resource == "" {
		// Authentication only: a user with no permissions at all passes the gate.
		id := "u-none-" + suffix
		p.drv.AddUser(testutil.User{ID: id, Role: "viewer"})
		if code := p.status(t, rp, id); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Fatalf("auth-only route rejected a valid token: %d", code)
		}
		return
	}

	want := rp.resource + ":" + rp.action
	var others []string
	for perm := range p.all {
		if perm != want {
			others = append(others, perm)
		}
	}
	sort.Strings(others)

	deniedID := "u-denied-" + suffix
	p.drv.AddUser(testutil.User{ID: deniedID, Role: "viewer", Permissions: others})
	if code := p.status(t, rp, deniedID); code != http.StatusForbidden {
		t.Fatalf("user with every other permission: got %d, want 403", code)
	}

	allowedID := "u-allowed-" + suffix
	p.drv.AddUser(testutil.User{ID: allowedID, Role: "viewer", Permissions: []string{want}})
	if code := p.status(t, rp, allowedID); code == http.StatusUnauthorized || code == http.StatusForbidden {
		t.Fatalf("user with exactly %s: got %d", want, code)
	}
}

var updateRoutes = flag.Bool("update-routes", false, "rewrite the route table golden")

const routesGolden = "testdata/routes.golden"

// chainToken names one handler of a route's chain by what it is, so the table
// does not move when the code that builds the middleware does.
func chainToken(name string) string {
	switch {
	case strings.Contains(name, "AuthMiddleware"):
		return "auth"
	case strings.Contains(name, "PermissionMiddleware"):
		return "can"
	case strings.Contains(strings.ToLower(name), "ratelimit"), strings.Contains(name, "(*limiter)"):
		return "limit"
	}
	return name[strings.LastIndex(name, "/")+1:]
}

// routeTable lists every route with its full handler chain, in order.
func routeTable(t *testing.T, core *Core) string {
	t.Helper()
	chains := map[string][]string{}
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		names := c.HandlerNames()[1:]
		chain := make([]string, 0, len(names))
		for _, n := range names {
			chain = append(chain, chainToken(n))
		}
		chains[c.Request.Method+" "+c.FullPath()] = chain
		c.Abort()
	})
	if err := Mount(engine.Group("/api"), core.Deps); err != nil {
		t.Fatal(err)
	}
	for _, r := range engine.Routes() {
		path := strings.Split(r.Path, "/")
		for i, seg := range path {
			if strings.HasPrefix(seg, ":") {
				path[i] = "x"
			}
		}
		do(engine, r.Method, strings.Join(path, "/"), "")
	}
	keys := make([]string, 0, len(chains))
	for k := range chains {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + " -> " + strings.Join(chains[k], " > ") + "\n")
	}
	return b.String()
}

func TestRouteTableIsPinned(t *testing.T) {
	plain, _ := newCore(t, nil)
	_, client := newMiniRedis(t)
	withRedis, _ := newCore(t, func(c *config.Config) { c.Redis = client })
	got := "# without Redis\n" + routeTable(t, plain) + "\n# with Redis\n" + routeTable(t, withRedis)
	if *updateRoutes {
		if err := os.MkdirAll(filepath.Dir(routesGolden), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(routesGolden, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(routesGolden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("route table changed:\n%s", got)
	}
}
