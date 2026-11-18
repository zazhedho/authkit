package authutil

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"

	"github.com/golang-jwt/jwt/v5"
)

const (
	DefaultAccessTTL  = 24 * time.Hour
	DefaultRefreshTTL = 168 * time.Hour
	DefaultResetTTL   = 900 * time.Second
)

// TokenConfig configures Tokens. Key needs 32+ characters. AppName is written
// to iss and aud and must match on verification; zero TTLs take defaults.
type TokenConfig struct {
	Key        string
	AppName    string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	ResetTTL   time.Duration
}

// Tokens issues and verifies HS256 JWTs with an injected key and TTLs.
type Tokens struct {
	key        []byte
	appName    string
	accessTTL  time.Duration
	refreshTTL time.Duration
	resetTTL   time.Duration
}

func NewTokens(cfg TokenConfig) (*Tokens, error) {
	key := strings.TrimSpace(cfg.Key)
	if key == "" {
		return nil, ErrJWTKeyNotConfigured
	}
	if len(key) < minJWTKeyLength {
		return nil, ErrJWTKeyTooShort
	}

	appName := strings.TrimSpace(cfg.AppName)
	if appName == "" {
		return nil, ErrAppNameRequired
	}

	t := &Tokens{
		key:        []byte(key),
		appName:    appName,
		accessTTL:  cfg.AccessTTL,
		refreshTTL: cfg.RefreshTTL,
		resetTTL:   cfg.ResetTTL,
	}
	if t.accessTTL <= 0 {
		t.accessTTL = DefaultAccessTTL
	}
	if t.refreshTTL <= 0 {
		t.refreshTTL = DefaultRefreshTTL
	}
	if t.resetTTL <= 0 {
		t.resetTTL = DefaultResetTTL
	}
	return t, nil
}

// AccessTTL and RefreshTTL return the defaults on a nil receiver, matching the
// other methods' fail-closed handling of a missing *Tokens.
func (t *Tokens) AccessTTL() time.Duration {
	if t == nil {
		return DefaultAccessTTL
	}
	return t.accessTTL
}

func (t *Tokens) RefreshTTL() time.Duration {
	if t == nil {
		return DefaultRefreshTTL
	}
	return t.refreshTTL
}

func (t *Tokens) Generate(user *domainuser.Users, logID string) (string, error) {
	return t.GenerateWithClaims(user, logID, nil)
}

func (t *Tokens) GeneratePasswordReset(user *domainuser.Users, logID string) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}
	resetExp := time.Now().Add(t.resetTTL)
	return t.GenerateWithClaims(user, logID, &AppClaims{
		TokenType: TokenTypePasswordReset,
		RegisteredClaims: &jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(resetExp),
		},
	})
}

func (t *Tokens) GenerateWithClaims(user *domainuser.Users, logID string, claimsOverride *AppClaims) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}

	accessExp := time.Now().Add(t.accessTTL)
	claims := AppClaims{
		UserId:    user.Id,
		Username:  user.Name,
		Role:      user.Role,
		TokenType: TokenTypeAccess,
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    t.appName,
			Audience:  jwt.ClaimStrings{t.appName},
			ID:        logID,
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if claimsOverride != nil {
		if claimsOverride.TokenType != "" {
			claims.TokenType = claimsOverride.TokenType
		}
		claims.IsImpersonated = claimsOverride.IsImpersonated
		claims.OriginalUserId = claimsOverride.OriginalUserId
		claims.OriginalUsername = claimsOverride.OriginalUsername
		claims.OriginalRole = claimsOverride.OriginalRole
		if claimsOverride.RegisteredClaims != nil && claimsOverride.ExpiresAt != nil {
			claims.ExpiresAt = claimsOverride.ExpiresAt
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	return token.SignedString(t.key)
}

func (t *Tokens) GenerateRefresh(user *domainuser.Users, logID string, claimsOverride *AppClaims) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}

	refreshExp := time.Now().Add(t.refreshTTL)
	claims := &AppClaims{
		UserId:    user.Id,
		Username:  user.Name,
		Role:      user.Role,
		TokenType: TokenTypeRefresh,
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    t.appName,
			Audience:  jwt.ClaimStrings{t.appName},
			ID:        logID,
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if claimsOverride != nil {
		claims.IsImpersonated = claimsOverride.IsImpersonated
		claims.OriginalUserId = claimsOverride.OriginalUserId
		claims.OriginalUsername = claimsOverride.OriginalUsername
		claims.OriginalRole = claimsOverride.OriginalRole
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(t.key)
}

func (t *Tokens) ClaimsFromRequest(request *http.Request) (string, map[string]any, error) {
	tokenString := GetAuthToken(request)
	data, err := t.Claims(tokenString)
	return tokenString, data, err
}

func (t *Tokens) Claims(tokenString string) (map[string]any, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}
	if t == nil {
		return nil, ErrJWTKeyNotConfigured
	}

	// // Claims is the only JWT parse; issuer and audience must match exactly, so
	// // tokens from other applications (or without them) are rejected.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return "", fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return t.key, nil
	}, jwt.WithIssuer(t.appName), jwt.WithAudience(t.appName))
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

func (t *Tokens) ExpiresAt(tokenString string) (time.Time, error) {
	claims, err := t.Claims(tokenString)
	if err != nil {
		return time.Time{}, errors.New("invalid or expired token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("token expiry is required")
	}

	return time.Unix(int64(exp), 0), nil
}
