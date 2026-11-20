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

// IssuedAtSkew is how far in the future an iat may be, for nodes whose clocks
// differ slightly. exp has no leeway.
const IssuedAtSkew = 30 * time.Second

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

// New validates cfg and creates the Tokens issuer.
func New(cfg Config) (*Tokens, error) {
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

// issuedAt is now, pushed to one millisecond past after (a revocation cut-off;
// zero for none), so a token issued right after a revocation is never void
// because of clock skew or rounding.
func issuedAt(after time.Time) time.Time {
	now := time.Now()
	if floor := after.Add(time.Millisecond); !after.IsZero() && now.Before(floor) {
		return floor
	}
	return now
}

// Generate issues an access token. The Generate methods take the user's id,
// name and role as plain strings so this package needs no domain type.
func (t *Tokens) Generate(userID, username, role string, after time.Time) (string, error) {
	return t.GenerateWithClaims(userID, username, role, nil, after)
}

// GenerateNoSession issues an access token that is not bound to a Redis session.
func (t *Tokens) GenerateNoSession(userID, username, role string, after time.Time) (string, error) {
	return t.GenerateWithClaims(userID, username, role, &AppClaims{NoSession: true}, after)
}

func (t *Tokens) GenerateWithClaims(userID, username, role string, claimsOverride *AppClaims, after time.Time) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}

	issued := issuedAt(after)
	accessExp := issued.Add(t.accessTTL)
	claims := AppClaims{
		UserID:     userID,
		Username:   username,
		Role:       role,
		TokenType:  TokenTypeAccess,
		IssuedAtMS: issued.UnixMilli(),
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    t.appName,
			Audience:  jwt.ClaimStrings{t.appName},
			ID:        uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(issued),
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
		claims.ActorSessionID = claimsOverride.ActorSessionID
		claims.ActorTokenHash = claimsOverride.ActorTokenHash
		if claims.IsImpersonated && t.accessTTL > maxImpersonationTTL {
			claims.ExpiresAt = jwt.NewNumericDate(issued.Add(maxImpersonationTTL))
		}
		if claimsOverride.RegisteredClaims != nil && claimsOverride.ExpiresAt != nil {
			claims.ExpiresAt = claimsOverride.ExpiresAt
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	return token.SignedString(t.key)
}

func (t *Tokens) GenerateRefresh(userID, username, role string, after time.Time) (string, error) {
	if t == nil {
		return "", ErrJWTKeyNotConfigured
	}

	issued := issuedAt(after)
	refreshExp := issued.Add(t.refreshTTL)
	claims := &AppClaims{
		UserID:     userID,
		Username:   username,
		Role:       role,
		TokenType:  TokenTypeRefresh,
		IssuedAtMS: issued.UnixMilli(),
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    t.appName,
			Audience:  jwt.ClaimStrings{t.appName},
			ID:        uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			IssuedAt:  jwt.NewNumericDate(issued),
		},
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
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(),
		jwt.WithIssuer(t.appName), jwt.WithAudience(t.appName))
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if iat, ok := claims["iat"].(float64); ok && time.Unix(int64(iat), 0).After(time.Now().Add(IssuedAtSkew)) {
			return nil, errors.New("token issued in the future")
		}
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
func (t *Tokens) GenerateImpersonated(userID, username, role, originalUserID, originalUsername, originalRole string, after time.Time) (string, error) {
	return t.GenerateWithClaims(userID, username, role, &AppClaims{
		IsImpersonated:   true,
		OriginalUserID:   originalUserID,
		OriginalUsername: originalUsername,
		OriginalRole:     originalRole,
	}, after)
}

// GenerateImpersonatedBound is GenerateImpersonated with the actor's session ID
// and access-token hash recorded in the token (either may be empty).
func (t *Tokens) GenerateImpersonatedBound(userID, username, role, originalUserID, originalUsername, originalRole, actorSessionID, actorTokenHash string, after time.Time) (string, error) {
	return t.GenerateWithClaims(userID, username, role, &AppClaims{
		IsImpersonated:   true,
		OriginalUserID:   originalUserID,
		OriginalUsername: originalUsername,
		OriginalRole:     originalRole,
		ActorSessionID:   actorSessionID,
		ActorTokenHash:   actorTokenHash,
	}, after)
}
