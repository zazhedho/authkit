package authutil

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const minJWTKeyLength = 32

const (
	TokenTypeAccess        = "access"
	TokenTypeRefresh       = "refresh"
	TokenTypePasswordReset = "password_reset"
)

var (
	ErrJWTKeyNotConfigured = errors.New("jwt key is not configured")
	ErrJWTKeyTooShort      = fmt.Errorf("jwt key must be at least %d characters", minJWTKeyLength)
)

type AppClaims struct {
	UserId           string `json:"user_id"`
	Username         string `json:"username"`
	Role             string `json:"role"`
	TokenType        string `json:"token_type,omitempty"`
	IsImpersonated   bool   `json:"is_impersonated,omitempty"`
	OriginalUserId   string `json:"original_user_id,omitempty"`
	OriginalUsername string `json:"original_username,omitempty"`
	OriginalRole     string `json:"original_role,omitempty"`
	*jwt.RegisteredClaims
}

func GetAuthToken(request *http.Request) string {
	if request == nil {
		return ""
	}
	bearerToken := request.Header.Get("Authorization")
	return strings.ReplaceAll(bearerToken, "Bearer ", "")
}
