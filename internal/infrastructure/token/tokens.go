package token

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// maxImpersonationTTL caps the life of an impersonation access token.
const maxImpersonationTTL = 15 * time.Minute

// Config configures Tokens. Key needs 32+ characters. AppName is written
// to iss and aud and must match on verification. The caller supplies every TTL.
type Config struct {
	Key        string
	AppName    string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// Tokens issues and verifies HS256 JWTs with an injected key and TTLs.
type Tokens struct {
	key        []byte
	appName    string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewTokens validates cfg and creates the Tokens issuer.
func NewTokens(cfg Config) (*Tokens, error) {
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

// RefreshTTL refreshes the TTL.
func (t *Tokens) RefreshTTL() time.Duration {
	if t == nil {
		return 0
	}
	return t.refreshTTL
}

// Generate issues an access token. The Generate methods take the user's id,
// name and role as plain strings so this package needs no domain type.
func (t *Tokens) Generate(userID, username, role, logID string) (string, error) {
	return t.GenerateWithClaims(userID, username, role, logID, nil)
}

// GenerateWithClaims generates the with claims.
func (t *Tokens) GenerateWithClaims(userID, username, role, logID string, claimsOverride *AppClaims) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}

	accessExp := time.Now().Add(t.accessTTL)
	claims := AppClaims{
		UserID:    userID,
		Username:  username,
		Role:      role,
		TokenType: TokenTypeAccess,
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    t.appName,
			Audience:  jwt.ClaimStrings{t.appName},
			ID:        uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if claimsOverride != nil {
		if claimsOverride.TokenType != "" {
			claims.TokenType = claimsOverride.TokenType
		}
		claims.IsImpersonated = claimsOverride.IsImpersonated
		claims.NoSession = claimsOverride.NoSession || claimsOverride.IsImpersonated
		claims.OriginalUserID = claimsOverride.OriginalUserID
		claims.OriginalUsername = claimsOverride.OriginalUsername
		claims.OriginalRole = claimsOverride.OriginalRole
		if claims.IsImpersonated && t.accessTTL > maxImpersonationTTL {
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(maxImpersonationTTL))
		}
		if claimsOverride.RegisteredClaims != nil && claimsOverride.ExpiresAt != nil {
			claims.ExpiresAt = claimsOverride.ExpiresAt
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	return token.SignedString(t.key)
}

// GenerateRefresh generates the refresh.
func (t *Tokens) GenerateRefresh(userID, username, role, logID string) (string, error) {
	return t.generateRefresh(userID, username, role, logID, nil)
}

// GenerateRefreshImpersonated issues a refresh token that keeps the original
// identity an impersonation started from.
func (t *Tokens) GenerateRefreshImpersonated(userID, username, role, logID, originalUserID, originalUsername, originalRole string) (string, error) {
	return t.generateRefresh(userID, username, role, logID, &AppClaims{
		IsImpersonated:   true,
		OriginalUserID:   originalUserID,
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
		UserID:    userID,
		Username:  username,
		Role:      role,
		TokenType: TokenTypeRefresh,
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    t.appName,
			Audience:  jwt.ClaimStrings{t.appName},
			ID:        uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if claimsOverride != nil {
		claims.IsImpersonated = claimsOverride.IsImpersonated
		claims.OriginalUserID = claimsOverride.OriginalUserID
		claims.OriginalUsername = claimsOverride.OriginalUsername
		claims.OriginalRole = claimsOverride.OriginalRole
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(t.key)
}

// ClaimsFromRequest implements the claims from request operation.
func (t *Tokens) ClaimsFromRequest(request *http.Request) (string, map[string]any, error) {
	tokenString := GetAuthToken(request)
	data, err := t.Claims(tokenString)
	return tokenString, data, err
}

// Claims implements the claims operation.
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
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt(),
		jwt.WithIssuer(t.appName), jwt.WithAudience(t.appName))
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// ExpiresAt implements the expires at operation.
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
		OriginalUserID:   originalUserID,
		OriginalUsername: originalUsername,
		OriginalRole:     originalRole,
	})
}
