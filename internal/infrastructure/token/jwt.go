package token

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const minJWTKeyLength = 32

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

var (
	ErrJWTKeyNotConfigured = errors.New("jwt key is not configured")
	ErrJWTKeyTooShort      = fmt.Errorf("jwt key must be at least %d characters", minJWTKeyLength)
	ErrAppNameRequired     = errors.New("app name is required to bind tokens to the issuing application")
)

type AppClaims struct {
	UserID         string `json:"user_id"`
	Username       string `json:"username"`
	Role           string `json:"role"`
	TokenType      string `json:"token_type,omitempty"`
	IsImpersonated bool   `json:"is_impersonated,omitempty"`
	// NoSession marks a token that has no Redis session: impersonation tokens
	// and tokens from Kit.IssueAccessToken.
	NoSession        bool   `json:"no_session,omitempty"`
	OriginalUserID   string `json:"original_user_id,omitempty"`
	OriginalUsername string `json:"original_username,omitempty"`
	OriginalRole     string `json:"original_role,omitempty"`
	// IssuedAtMS is iat in milliseconds; the registered iat only has seconds.
	IssuedAtMS int64 `json:"iat_ms,omitempty"`
	*jwt.RegisteredClaims
}

func GetAuthToken(request *http.Request) string {
	if request == nil {
		return ""
	}
	token, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(token)
}
