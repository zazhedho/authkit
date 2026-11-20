package authkit

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

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

func newMiniRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func mountedEngine(t *testing.T, kit *Kit) *gin.Engine {
	t.Helper()
	engine := gin.New()
	kit.Mount(engine.Group("/api"))
	return engine
}

func TestMountRegistersExactlyBaseRoutesWithoutRedis(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	requireSameRoutes(t, registeredRoutes(mountedEngine(t, kit)), baseRoutes)
	if len(baseRoutes) != 42 {
		t.Fatalf("baseRoutes has %d entries, want 42", len(baseRoutes))
	}
}

func TestMountRegistersSessionRoutesWithRedis(t *testing.T) {
	_, client := newMiniRedis(t)
	kit, _ := newTestKit(t, func(c *Config) { c.Redis = client })
	requireSameRoutes(t, registeredRoutes(mountedEngine(t, kit)), sortedCopy(baseRoutes, sessionRoutes))
}

func TestMountRegistersSessionRoutesWithRedisButNoMailer(t *testing.T) {
	// Redis without Mailer still mounts sessions; OTP and reset stay inert.
	_, client := newMiniRedis(t)
	kit, _ := newTestKit(t, func(c *Config) { c.Redis = client; c.Mailer = nil })
	requireSameRoutes(t, registeredRoutes(mountedEngine(t, kit)), sortedCopy(baseRoutes, sessionRoutes))
}

func TestMountCanServeTwoGroups(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	engine := gin.New()
	kit.Mount(engine.Group("/api"))
	kit.Mount(engine.Group("/v2"))

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
	kit, _ := newTestKit(t, nil)
	if code := do(mountedEngine(t, kit), http.MethodGet, "/api/users", "").Code; code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", code)
	}
}

func TestPublicRouteNeedsNoToken(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	if code := do(mountedEngine(t, kit), http.MethodGet, "/api/user/register/status", "").Code; code != http.StatusOK {
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

func TestMountAppliesPermissionPerRoute(t *testing.T) {
	_, client := newMiniRedis(t)
	kit, drv := newTestKit(t, func(c *Config) { c.Redis = client })
	engine := mountedEngine(t, kit)

	// Every distinct permission any route demands.
	all := map[string]bool{}
	for _, rp := range routePermissions {
		if rp.resource != "" {
			all[rp.resource+":"+rp.action] = true
		}
	}

	for _, rp := range routePermissions {
		name := rp.method + " " + rp.path
		t.Run(name, func(t *testing.T) {
			if code := do(engine, rp.method, rp.path, "").Code; code != http.StatusUnauthorized {
				t.Fatalf("no token: got %d, want 401", code)
			}

			if rp.resource == "" {
				// Authentication only: a user with no permissions at all passes the gate.
				id := "u-none-" + strings.ReplaceAll(name, " ", "_")
				drv.AddUser(testutil.User{ID: id, Role: "viewer"})
				code := do(engine, rp.method, rp.path, tokenFor(t, kit, id, "viewer")).Code
				if code == http.StatusUnauthorized || code == http.StatusForbidden {
					t.Fatalf("auth-only route rejected a valid token: %d", code)
				}
				return
			}

			want := rp.resource + ":" + rp.action
			var others []string
			for p := range all {
				if p != want {
					others = append(others, p)
				}
			}
			sort.Strings(others)

			deniedID := "u-denied-" + strings.ReplaceAll(name, " ", "_")
			drv.AddUser(testutil.User{ID: deniedID, Role: "viewer", Permissions: others})
			if code := do(engine, rp.method, rp.path, tokenFor(t, kit, deniedID, "viewer")).Code; code != http.StatusForbidden {
				t.Fatalf("user with every other permission: got %d, want 403", code)
			}

			allowedID := "u-allowed-" + strings.ReplaceAll(name, " ", "_")
			drv.AddUser(testutil.User{ID: allowedID, Role: "viewer", Permissions: []string{want}})
			code := do(engine, rp.method, rp.path, tokenFor(t, kit, allowedID, "viewer")).Code
			if code == http.StatusUnauthorized || code == http.StatusForbidden {
				t.Fatalf("user with exactly %s: got %d", want, code)
			}
		})
	}
}

var updateRoutes = flag.Bool("update-routes", false, "rewrite the route table golden")

const routesGolden = "internal/router/testdata/routes.golden"

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
func routeTable(t *testing.T, kit *Kit) string {
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
	kit.Mount(engine.Group("/api"))
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
	plain, _ := newTestKit(t, nil)
	_, client := newMiniRedis(t)
	withRedis, _ := newTestKit(t, func(c *Config) { c.Redis = client })
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
