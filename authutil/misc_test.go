package authutil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	domainuser "github.com/zazhedho/authkit/domain/user"

	"github.com/gin-gonic/gin"
)

func TestJwtClaimsReadsAuthorizationHeader(t *testing.T) {
	t.Setenv("JWT_KEY", "test-secret-must-be-at-least-32-bytes")
	token, err := GenerateJwt(&domainuser.Users{
		Id:   "user-1",
		Name: "Jane",
		Role: RoleViewer,
	}, "log-1")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.Header.Set("Authorization", "Bearer "+token)

	tokenString, claims, err := JwtClaims(ctx.Request)
	if err != nil || tokenString != token || claims["user_id"] == "" {
		t.Fatalf("jwt claims: token=%q claims=%+v err=%v", tokenString, claims, err)
	}
}
