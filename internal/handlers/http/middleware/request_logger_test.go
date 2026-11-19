package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zazhedho/gokit"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"

	"github.com/gin-gonic/gin"
)

func TestRequestLoggerAndRecoveryMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestLogger())
	router.Use(gokit.Recovery())
	router.GET("/panic", func(ctx *gin.Context) {
		panic("boom")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	req = req.WithContext(domainauth.WithContext(req.Context(), domainauth.New("user-1", "Jane", "viewer", nil)))
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRoleMiddlewareAllowsAndRejectsRoles(t *testing.T) {
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)

	rec := performMiddlewareRequest(
		testToken(t, "access", domainuser.RoleAdmin),
		mdw.AuthMiddleware(),
		mdw.RoleMiddleware(domainuser.RoleAdmin),
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected admin role to pass, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = performMiddlewareRequest(
		testToken(t, "access", domainuser.RoleViewer),
		mdw.AuthMiddleware(),
		mdw.RoleMiddleware(domainuser.RoleAdmin),
	)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected viewer role to be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
}
