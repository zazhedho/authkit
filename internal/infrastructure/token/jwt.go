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
	// TokenTypeAccess is the token type access constant.
	TokenTypeAccess = "access"
	// TokenTypeRefresh is the token type refresh constant.
	TokenTypeRefresh = "refresh"
)

var (
	// ErrJWTKeyNotConfigured is returned for the JWT key not configured case.
	ErrJWTKeyNotConfigured = errors.New("jwt key is not configured")
	// ErrJWTKeyTooShort is returned for the JWT key too short case.
	ErrJWTKeyTooShort = fmt.Errorf("jwt key must be at least %d characters", minJWTKeyLength)
	// ErrAppNameRequired is returned for the app name required case.
	ErrAppNameRequired = errors.New("app name is required to bind tokens to the issuing application")
)

// AppClaims is the app claims.
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
	*jwt.RegisteredClaims
}

// GetAuthToken returns the auth token.
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
