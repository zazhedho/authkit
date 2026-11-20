package authkit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit"
	"github.com/zazhedho/authkit/internal/testutil"
)

const testJWTKey = "test-secret-must-be-at-least-32-bytes"

// TestFacade builds a Kit and uses it through the public API only: New
// validates, Mount succeeds, Auth and Can guard a route, and the scope helpers
// round-trip. The wiring itself is tested in internal/router.
func TestFacade(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, drv := testutil.NewDB(t)

	for name, cfg := range map[string]authkit.Config{
		"nil DB":         {AppName: "app", JWTKey: testJWTKey},
		"short JWT key":  {DB: db, AppName: "app", JWTKey: "too-short"},
		"empty app name": {DB: db, JWTKey: testJWTKey},
	} {
		if _, err := authkit.New(cfg); err == nil {
			t.Errorf("New accepted a config with %s", name)
		}
	}

	kit, err := authkit.New(authkit.Config{DB: db, AppName: "app", JWTKey: testJWTKey})
	if err != nil {
		t.Fatal(err)
	}
	if len(drv.Queries()) != 0 {
		t.Fatalf("New must not query the database, got %v", drv.Queries())
	}
	if kit.Audit() == nil || kit.AppConfig() == nil {
		t.Fatal("accessors must be non-nil")
	}

	drv.AddUser(testutil.User{ID: "user-7", Role: authkit.RoleStaff, Permissions: []string{"trips:create"}})
	drv.AddUser(testutil.User{ID: "user-8", Role: authkit.RoleStaff})
	engine := gin.New()
	if err := kit.Mount(engine.Group("/api")); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	engine.GET("/who", kit.Auth(), kit.Can("trips", "create"), func(c *gin.Context) {
		s := authkit.ScopeFrom(c.Request.Context())
		c.JSON(http.StatusOK, gin.H{"id": s.UserID, "name": s.Username, "role": s.Role})
	})

	get := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/who", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec
	}
	allowed, err := kit.IssueAccessToken("user-7", "Seven", authkit.RoleStaff)
	if err != nil {
		t.Fatal(err)
	}
	denied, _ := kit.IssueAccessToken("user-8", "Eight", authkit.RoleStaff)
	if rec := get(allowed); rec.Code != http.StatusOK {
		t.Fatalf("holder of trips:create: %d %s", rec.Code, rec.Body.String())
	} else {
		var got map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got["id"] != "user-7" || got["name"] != "Seven" || got["role"] != authkit.RoleStaff {
			t.Fatalf("scope = %v (%v)", got, err)
		}
	}
	if code := get(denied).Code; code != http.StatusForbidden {
		t.Fatalf("user without the permission: %d, want 403", code)
	}
	if code := get("").Code; code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", code)
	}

	ctx := authkit.WithScope(context.Background(), authkit.NewScope("u1", "One", authkit.RoleViewer, []string{"trips:view"}))
	if s := authkit.ScopeFrom(ctx); s.UserID != "u1" || s.Role != authkit.RoleViewer || !s.Has("trips", "view") || s.Has("trips", "delete") {
		t.Fatalf("scope round trip failed: %+v", s)
	}

	shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := kit.Close(shutdown); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
