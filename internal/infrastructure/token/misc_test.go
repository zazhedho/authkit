package token

import (
	"net/http"
	"net/http/httptest"
	"testing"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"

	"github.com/gin-gonic/gin"
)

func TestClaimsFromRequestReadsAuthorizationHeader(t *testing.T) {
	tokens := newTestTokens(t)
	token, err := tokens.Generate("user-1", "Jane", domainuser.RoleViewer, "log-1")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.Header.Set("Authorization", "Bearer "+token)

	tokenString, claims, err := tokens.ClaimsFromRequest(ctx.Request)
	if err != nil || tokenString != token || claims["user_id"] == "" {
		t.Fatalf("jwt claims: token=%q claims=%+v err=%v", tokenString, claims, err)
	}
}
