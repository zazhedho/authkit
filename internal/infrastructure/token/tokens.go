package token

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenConfig configures Tokens. Key needs 32+ characters. AppName is written
// to iss and aud and must match on verification. The caller supplies every TTL.
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
	return t, nil
}

// AccessTTL and RefreshTTL return zero on a nil receiver, matching the other
// methods' fail-closed handling of a missing *Tokens.
func (t *Tokens) AccessTTL() time.Duration {
	if t == nil {
		return 0
	}
	return t.accessTTL
}

func (t *Tokens) RefreshTTL() time.Duration {
	if t == nil {
		return 0
	}
	return t.refreshTTL
}

// The Generate methods take the user's id, name and role as plain strings so
// this package needs no domain type.
func (t *Tokens) Generate(userID, username, role, logID string) (string, error) {
	return t.GenerateWithClaims(userID, username, role, logID, nil)
}

func (t *Tokens) GeneratePasswordReset(userID, username, role, logID string) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}
	resetExp := time.Now().Add(t.resetTTL)
	return t.GenerateWithClaims(userID, username, role, logID, &AppClaims{
		TokenType: TokenTypePasswordReset,
		RegisteredClaims: &jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(resetExp),
		},
	})
}

func (t *Tokens) GenerateWithClaims(userID, username, role, logID string, claimsOverride *AppClaims) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}

	accessExp := time.Now().Add(t.accessTTL)
	claims := AppClaims{
		UserId:    userID,
		Username:  username,
		Role:      role,
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

func (t *Tokens) GenerateRefresh(userID, username, role, logID string) (string, error) {
	return t.generateRefresh(userID, username, role, logID, nil)
}

// GenerateRefreshImpersonated issues a refresh token that keeps the original
// identity an impersonation started from.
func (t *Tokens) GenerateRefreshImpersonated(userID, username, role, logID, originalUserID, originalUsername, originalRole string) (string, error) {
	return t.generateRefresh(userID, username, role, logID, &AppClaims{
		IsImpersonated:   true,
		OriginalUserId:   originalUserID,
		OriginalUsername: originalUsername,
		OriginalRole:     originalRole,
	})
}

func (t *Tokens) generateRefresh(userID, username, role, logID string, claimsOverride *AppClaims) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}

	refreshExp := time.Now().Add(t.refreshTTL)
	claims := &AppClaims{
		UserId:    userID,
		Username:  username,
		Role:      role,
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

	// Claims is the only JWT parse; issuer and audience must match exactly, so
	// tokens from other applications (or without them) are rejected.
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

// GenerateImpersonated issues an access token that records the original identity
// the impersonation started from.
func (t *Tokens) GenerateImpersonated(userID, username, role, logID, originalUserID, originalUsername, originalRole string) (string, error) {
	return t.GenerateWithClaims(userID, username, role, logID, &AppClaims{
		IsImpersonated:   true,
		OriginalUserId:   originalUserID,
		OriginalUsername: originalUsername,
		OriginalRole:     originalRole,
	})
}

// IsPasswordResetClaims reports whether parsed claims belong to a password
// reset token.
func (t *Tokens) IsPasswordResetClaims(claims map[string]any) bool {
	tokenType, _ := claims["token_type"].(string)
	return tokenType == TokenTypePasswordReset
}
