package token

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const testJWTKey = "test-secret-must-be-at-least-32-bytes"

func newTestTokens(t *testing.T) *Tokens {
	t.Helper()
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: "test-app", AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour, ResetTTL: 15 * time.Minute})
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
			tokens, err := NewTokens(TokenConfig{Key: tc.key, AppName: "test-app", AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour, ResetTTL: 15 * time.Minute})
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
	if _, err := NewTokens(TokenConfig{Key: strings.Repeat("k", 32), AppName: "test-app", AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour, ResetTTL: 15 * time.Minute}); err != nil {
		t.Fatalf("expected 32 character key to be valid, got %v", err)
	}
}

func TestNewTokensUsesInjectedTTLs(t *testing.T) {
	tokens := newTestTokens(t)
	if tokens.AccessTTL() != time.Hour {
		t.Fatalf("expected injected access TTL 1h, got %v", tokens.AccessTTL())
	}
	if tokens.RefreshTTL() != 2*time.Hour {
		t.Fatalf("expected injected refresh TTL 2h, got %v", tokens.RefreshTTL())
	}

	token, err := tokens.GeneratePasswordReset("user-1", "", "", "reset-1")
	if err != nil {
		t.Fatalf("GeneratePasswordReset: %v", err)
	}
	expiresAt, err := tokens.ExpiresAt(token)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	assertExpiresAround(t, expiresAt, 15*time.Minute)
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

	token, err := tokens.Generate("user-1", "Jane", roleViewer, "log-1")
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
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: "test-app", AccessTTL: 2 * time.Hour, RefreshTTL: 2 * time.Hour, ResetTTL: 15 * time.Minute})
	if err != nil {
		t.Fatalf("NewTokens: %v", err)
	}

	token, err := tokens.Generate("user-1", "", "", "log-1")
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
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: "test-app", RefreshTTL: 48 * time.Hour, AccessTTL: time.Hour, ResetTTL: 15 * time.Minute})
	if err != nil {
		t.Fatalf("NewTokens: %v", err)
	}

	token, err := tokens.GenerateRefresh("user-1", "Jane", roleViewer, "log-1")
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

	token, err := tokens.GenerateWithClaims("user-1", "", "", "log-1", override)
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
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: "test-app", ResetTTL: 10 * time.Minute, AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("NewTokens: %v", err)
	}

	token, err := tokens.GeneratePasswordReset("user-1", "", "", "reset-1")
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

	token, err := tokens.Generate("user-1", "Jane", roleViewer, "log-1")
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": "user-1", "iss": "test-app", "aud": []string{"test-app"}})
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
	token, err := tokens.Generate("user-1", "", "", "log-1")
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
	user := &testUser{Id: "user-1"}

	if _, err := tokens.Generate(user.Id, user.Name, user.Role, "log-1"); !errors.Is(err, ErrJWTKeyNotConfigured) {
		t.Fatalf("expected jwt key error for access token, got %v", err)
	}
	if _, err := tokens.GenerateRefresh(user.Id, user.Name, user.Role, "log-1"); !errors.Is(err, ErrJWTKeyNotConfigured) {
		t.Fatalf("expected jwt key error for refresh token, got %v", err)
	}
	if _, err := tokens.GeneratePasswordReset(user.Id, user.Name, user.Role, "log-1"); !errors.Is(err, ErrJWTKeyNotConfigured) {
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

func TestNilTokensTTLsAreZero(t *testing.T) {
	var tokens *Tokens
	if tokens.AccessTTL() != 0 || tokens.RefreshTTL() != 0 {
		t.Fatalf("expected zero TTLs on nil receiver, got %v %v", tokens.AccessTTL(), tokens.RefreshTTL())
	}
}

func newTokensForApp(t *testing.T, app string) *Tokens {
	t.Helper()
	tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: app, AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour, ResetTTL: 15 * time.Minute})
	if err != nil {
		t.Fatalf("NewTokens(%q): %v", app, err)
	}
	return tokens
}

// issueEachTokenType returns one token of every type the issuer can mint.
func issueEachTokenType(t *testing.T, tokens *Tokens) map[string]string {
	t.Helper()
	user := &testUser{Id: "user-1", Name: "Jane", Role: roleViewer}
	access, err := tokens.Generate(user.Id, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	refresh, err := tokens.GenerateRefresh(user.Id, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("GenerateRefresh: %v", err)
	}
	reset, err := tokens.GeneratePasswordReset(user.Id, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("GeneratePasswordReset: %v", err)
	}
	return map[string]string{"access": access, "refresh": refresh, "reset": reset}
}

func TestTokensCarryIssuerAndAudience(t *testing.T) {
	a := newTokensForApp(t, "app-a")
	for name, token := range issueEachTokenType(t, a) {
		t.Run(name, func(t *testing.T) {
			claims, err := a.Claims(token)
			if err != nil {
				t.Fatalf("Claims: %v", err)
			}
			if claims["iss"] != "app-a" {
				t.Fatalf("expected iss app-a, got %v", claims["iss"])
			}
			aud, ok := claims["aud"].([]any)
			if !ok || len(aud) != 1 || aud[0] != "app-a" {
				t.Fatalf("expected aud [app-a], got %v", claims["aud"])
			}
		})
	}
}

func TestClaimsRejectsTokenFromOtherApp(t *testing.T) {
	a := newTokensForApp(t, "app-a")
	b := newTokensForApp(t, "app-b")
	for name, token := range issueEachTokenType(t, a) {
		t.Run(name, func(t *testing.T) {
			if _, err := b.Claims(token); err == nil {
				t.Fatal("expected token from another app to be rejected")
			}
			if _, err := b.ExpiresAt(token); err == nil {
				t.Fatal("expected ExpiresAt to reject token from another app")
			}
		})
	}
}

func TestClaimsRejectsTokenWithoutIssuerOrAudience(t *testing.T) {
	b := newTokensForApp(t, "app-b")
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))
	cases := map[string]jwt.MapClaims{
		"neither":             {"user_id": "user-1", "exp": exp},
		"issuer only":         {"user_id": "user-1", "exp": exp, "iss": "app-b"},
		"audience only":       {"user_id": "user-1", "exp": exp, "aud": []string{"app-b"}},
		"wrong issuer":        {"user_id": "user-1", "exp": exp, "iss": "app-a", "aud": []string{"app-b"}},
		"wrong audience":      {"user_id": "user-1", "exp": exp, "iss": "app-b", "aud": []string{"app-a"}},
		"empty audience list": {"user_id": "user-1", "exp": exp, "iss": "app-b", "aud": []string{}},
		"different case":      {"user_id": "user-1", "exp": exp, "iss": "APP-B", "aud": []string{"app-b"}},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTKey))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if _, err := b.Claims(signed); err == nil {
				t.Fatal("expected token to be rejected")
			}
		})
	}
}

func TestClaimsAcceptsOwnToken(t *testing.T) {
	a := newTokensForApp(t, "app-a")
	for name, token := range issueEachTokenType(t, a) {
		t.Run(name, func(t *testing.T) {
			if _, err := a.Claims(token); err != nil {
				t.Fatalf("expected own token to be accepted, got %v", err)
			}
		})
	}
}

func TestClaimsAcceptsAudienceListContainingApp(t *testing.T) {
	b := newTokensForApp(t, "app-b")
	claims := jwt.MapClaims{
		"user_id": "user-1",
		"exp":     jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"iss":     "app-b",
		"aud":     []string{"other-service", "app-b"},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTKey))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := b.Claims(signed); err != nil {
		t.Fatalf("expected audience list containing the app to be accepted, got %v", err)
	}
}

func TestNewTokensRequiresAppName(t *testing.T) {
	for _, name := range []string{"", "  "} {
		tokens, err := NewTokens(TokenConfig{Key: testJWTKey, AppName: name, AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour, ResetTTL: 15 * time.Minute})
		if !errors.Is(err, ErrAppNameRequired) {
			t.Fatalf("AppName %q: expected ErrAppNameRequired, got %v", name, err)
		}
		if tokens != nil {
			t.Fatalf("AppName %q: expected nil tokens on error", name)
		}
	}
}

func TestNewTokensTrimsAppName(t *testing.T) {
	padded := newTokensForApp(t, "  app-a  ")
	exact := newTokensForApp(t, "app-a")
	token := issueEachTokenType(t, padded)["access"]
	claims, err := exact.Claims(token)
	if err != nil {
		t.Fatalf("expected trimmed app name to match, got %v", err)
	}
	if claims["iss"] != "app-a" {
		t.Fatalf("expected iss app-a, got %v", claims["iss"])
	}
}

func TestGenerateImpersonatedRecordsOriginalIdentity(t *testing.T) {
	tokens := newTestTokens(t)

	token, err := tokens.GenerateImpersonated("target", "Target", "viewer", "log-1", "root", "Root", "superadmin")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	claims, err := tokens.Claims(token)
	if err != nil {
		t.Fatalf("expected valid token, got %v", err)
	}
	if claims["user_id"] != "target" || claims["is_impersonated"] != true ||
		claims["original_user_id"] != "root" || claims["original_username"] != "Root" || claims["original_role"] != "superadmin" {
		t.Fatalf("unexpected impersonation claims: %+v", claims)
	}
}

func TestIsPasswordResetClaims(t *testing.T) {
	tokens := newTestTokens(t)
	user := &testUser{Id: "user-1"}

	reset, _ := tokens.GeneratePasswordReset(user.Id, user.Name, user.Role, "log")
	access, _ := tokens.Generate(user.Id, user.Name, user.Role, "log")
	resetClaims, _ := tokens.Claims(reset)
	accessClaims, _ := tokens.Claims(access)

	if !tokens.IsPasswordResetClaims(resetClaims) {
		t.Fatalf("expected reset claims to match, got %+v", resetClaims)
	}
	if tokens.IsPasswordResetClaims(accessClaims) || tokens.IsPasswordResetClaims(nil) {
		t.Fatal("access claims and nil claims must not match")
	}
}
