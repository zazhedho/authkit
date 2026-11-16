package authutil

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	domainuser "github.com/zazhedho/authkit/domain/user"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const testJWTKey = "test-secret-must-be-at-least-32-bytes"

func newTestTokens(t *testing.T) *Tokens {
	t.Helper()
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: "test-app"})
	if err != nil {
		t.Fatalf("NewTokens: %v", err)
	}
	return tokens
}

func TestNewTokensRejectsMissingOrShortKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want error
	}{
		{"empty", "", ErrJWTKeyNotConfigured},
		{"whitespace only", "   ", ErrJWTKeyNotConfigured},
		{"31 characters", strings.Repeat("k", 31), ErrJWTKeyTooShort},
		{"short", "a", ErrJWTKeyTooShort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokens, err := NewTokens(TokenConfig{Key: tc.key, AppName: "test-app"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			if tokens != nil {
				t.Fatal("expected nil tokens on error")
			}
		})
	}
}

func TestNewTokensAcceptsMinimumLengthKey(t *testing.T) {
	if _, err := NewTokens(TokenConfig{Key: strings.Repeat("k", 32), AppName: "test-app"}); err != nil {
		t.Fatalf("expected 32 character key to be valid, got %v", err)
	}
}

func TestNewTokensAppliesDefaultTTLs(t *testing.T) {
	tokens := newTestTokens(t)
	if tokens.AccessTTL() != 24*time.Hour {
		t.Fatalf("expected default access TTL 24h, got %v", tokens.AccessTTL())
	}
	if tokens.RefreshTTL() != 168*time.Hour {
		t.Fatalf("expected default refresh TTL 168h, got %v", tokens.RefreshTTL())
	}

	token, err := tokens.GeneratePasswordReset(&domainuser.Users{Id: "user-1"}, "reset-1")
	if err != nil {
		t.Fatalf("GeneratePasswordReset: %v", err)
	}
	expiresAt, err := tokens.ExpiresAt(token)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	assertExpiresAround(t, expiresAt, 900*time.Second)
}

func assertExpiresAround(t *testing.T, expiresAt time.Time, ttl time.Duration) {
	t.Helper()
	diff := time.Until(expiresAt) - ttl
	if diff > 5*time.Second || diff < -5*time.Second {
		t.Fatalf("expected expiry about now+%v, got %v (diff %v)", ttl, expiresAt, diff)
	}
}

func TestGenerateIncludesAccessClaims(t *testing.T) {
	tokens := newTestTokens(t)

	token, err := tokens.Generate(&domainuser.Users{
		Id:   "user-1",
		Name: "Jane",
		Role: RoleViewer,
	}, "log-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	claims, err := tokens.Claims(token)
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}

	if claims["user_id"] != "user-1" || claims["token_type"] != "access" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestGenerateExpiryFollowsAccessTTL(t *testing.T) {
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: "test-app", AccessTTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("NewTokens: %v", err)
	}

	token, err := tokens.Generate(&domainuser.Users{Id: "user-1"}, "log-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	expiresAt, err := tokens.ExpiresAt(token)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	assertExpiresAround(t, expiresAt, 2*time.Hour)
	if tokens.AccessTTL() != 2*time.Hour {
		t.Fatalf("expected AccessTTL 2h, got %v", tokens.AccessTTL())
	}
}

func TestGenerateRefreshIncludesRefreshTokenType(t *testing.T) {
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: "test-app", RefreshTTL: 48 * time.Hour})
	if err != nil {
		t.Fatalf("NewTokens: %v", err)
	}

	token, err := tokens.GenerateRefresh(&domainuser.Users{
		Id:   "user-1",
		Name: "Jane",
		Role: RoleViewer,
	}, "log-1", nil)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	claims, err := tokens.Claims(token)
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
	if claims["token_type"] != "refresh" {
		t.Fatalf("expected refresh token type, got %+v", claims)
	}
	expiresAt, err := tokens.ExpiresAt(token)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	assertExpiresAround(t, expiresAt, 48*time.Hour)
	if tokens.RefreshTTL() != 48*time.Hour {
		t.Fatalf("expected RefreshTTL 48h, got %v", tokens.RefreshTTL())
	}
}

func TestGenerateWithClaimsAppliesOverride(t *testing.T) {
	tokens := newTestTokens(t)
	override := &AppClaims{
		IsImpersonated: true,
		OriginalUserId: "admin-1",
		RegisteredClaims: &jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token, err := tokens.GenerateWithClaims(&domainuser.Users{Id: "user-1"}, "log-1", override)
	if err != nil {
		t.Fatalf("GenerateWithClaims: %v", err)
	}
	claims, err := tokens.Claims(token)
	if err != nil {
		t.Fatalf("Claims: %v", err)
	}
	if claims["is_impersonated"] != true || claims["original_user_id"] != "admin-1" {
		t.Fatalf("expected impersonation claims, got %+v", claims)
	}
	expiresAt, err := tokens.ExpiresAt(token)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	assertExpiresAround(t, expiresAt, time.Hour)
}

func TestGeneratePasswordResetIncludesDedicatedTokenType(t *testing.T) {
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: "test-app", ResetTTL: 10 * time.Minute})
	if err != nil {
		t.Fatalf("NewTokens: %v", err)
	}

	token, err := tokens.GeneratePasswordReset(&domainuser.Users{Id: "user-1"}, "reset-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	claims, err := tokens.Claims(token)
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
	if claims["token_type"] != TokenTypePasswordReset {
		t.Fatalf("expected password reset token type, got %+v", claims)
	}
	expiresAt, err := tokens.ExpiresAt(token)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	assertExpiresAround(t, expiresAt, 10*time.Minute)
}

func TestExpiresAt(t *testing.T) {
	tokens := newTestTokens(t)

	token, err := tokens.Generate(&domainuser.Users{
		Id:   "user-1",
		Name: "Jane",
		Role: RoleViewer,
	}, "log-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	expiresAt, err := tokens.ExpiresAt(token)
	if err != nil {
		t.Fatalf("expected token expiry, got %v", err)
	}
	if expiresAt.IsZero() || time.Until(expiresAt) <= 0 {
		t.Fatalf("expected future token expiry, got %v", expiresAt)
	}
}

func TestExpiresAtRequiresExpClaim(t *testing.T) {
	tokens := newTestTokens(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "user-1"})
	tokenString, err := token.SignedString([]byte(testJWTKey))
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}

	if _, err := tokens.ExpiresAt(tokenString); err == nil || err.Error() != "token expiry is required" {
		t.Fatalf("expected token expiry error, got %v", err)
	}
}

func TestClaimsRejectsUnexpectedSigningMethod(t *testing.T) {
	tokens := newTestTokens(t)

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"user_id": "user-1"})
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to sign none token: %v", err)
	}

	if _, err := tokens.Claims(tokenString); err == nil {
		t.Fatal("expected signing method error")
	}
}

func TestClaimsRejectsTokenSignedWithOtherKey(t *testing.T) {
	tokens := newTestTokens(t)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "user-1"})
	tokenString, err := token.SignedString([]byte("a-different-secret-of-at-least-32-bytes"))
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	if _, err := tokens.Claims(tokenString); err == nil {
		t.Fatal("expected signature error for token signed with another key")
	}
}

func TestClaimsRejectsEmptyToken(t *testing.T) {
	tokens := newTestTokens(t)
	if _, err := tokens.Claims(""); err == nil {
		t.Fatal("expected empty token error")
	}
}

func TestClaimsFromRequestReadsBearerToken(t *testing.T) {
	tokens := newTestTokens(t)
	token, err := tokens.Generate(&domainuser.Users{Id: "user-1"}, "log-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	raw, claims, err := tokens.ClaimsFromRequest(req)
	if err != nil {
		t.Fatalf("ClaimsFromRequest: %v", err)
	}
	if raw != token || claims["user_id"] != "user-1" {
		t.Fatalf("unexpected result: raw=%q claims=%+v", raw, claims)
	}
}

func TestNilTokensReportKeyNotConfigured(t *testing.T) {
	var tokens *Tokens
	user := &domainuser.Users{Id: "user-1"}

	if _, err := tokens.Generate(user, "log-1"); !errors.Is(err, ErrJWTKeyNotConfigured) {
		t.Fatalf("expected jwt key error for access token, got %v", err)
	}
	if _, err := tokens.GenerateRefresh(user, "log-1", nil); !errors.Is(err, ErrJWTKeyNotConfigured) {
		t.Fatalf("expected jwt key error for refresh token, got %v", err)
	}
	if _, err := tokens.GeneratePasswordReset(user, "log-1"); !errors.Is(err, ErrJWTKeyNotConfigured) {
		t.Fatalf("expected jwt key error for reset token, got %v", err)
	}
	if _, err := tokens.Claims("anything"); !errors.Is(err, ErrJWTKeyNotConfigured) {
		t.Fatalf("expected jwt key error for parsing, got %v", err)
	}
}

func TestGetAuthTokenStripsBearerPrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/", nil)
	ctx.Request.Header.Set("Authorization", "Bearer abc.def.ghi")

	if got := GetAuthToken(ctx.Request); got != "abc.def.ghi" {
		t.Fatalf("expected stripped bearer token, got %q", got)
	}
}

func TestNilTokensTTLsFallBackToDefaults(t *testing.T) {
	var tokens *Tokens
	if tokens.AccessTTL() != 24*time.Hour {
		t.Fatalf("expected default access TTL on nil receiver, got %v", tokens.AccessTTL())
	}
	if tokens.RefreshTTL() != 168*time.Hour {
		t.Fatalf("expected default refresh TTL on nil receiver, got %v", tokens.RefreshTTL())
	}
}
