package token

import (
	"errors"
	"net/http"
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
	tokens, err := NewTokens(Config{Key: testJWTKey, AppName: "test-app", AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour})
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
			tokens, err := NewTokens(Config{Key: tc.key, AppName: "test-app", AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour})
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
	if _, err := NewTokens(Config{Key: strings.Repeat("k", 32), AppName: "test-app", AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour}); err != nil {
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
	tokens, err := NewTokens(Config{Key: testJWTKey, AppName: "test-app", AccessTTL: 2 * time.Hour, RefreshTTL: 2 * time.Hour})
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
	tokens, err := NewTokens(Config{Key: testJWTKey, AppName: "test-app", RefreshTTL: 48 * time.Hour, AccessTTL: time.Hour})
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
		OriginalUserID: "admin-1",
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

	if _, err := tokens.ExpiresAt(tokenString); err == nil {
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
	user := &testUser{ID: "user-1"}

	if _, err := tokens.Generate(user.ID, user.Name, user.Role, "log-1"); !errors.Is(err, ErrJWTKeyNotConfigured) {
		t.Fatalf("expected jwt key error for access token, got %v", err)
	}
	if _, err := tokens.GenerateRefresh(user.ID, user.Name, user.Role, "log-1"); !errors.Is(err, ErrJWTKeyNotConfigured) {
		t.Fatalf("expected jwt key error for refresh token, got %v", err)
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
	tokens, err := NewTokens(Config{Key: testJWTKey, AppName: app, AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("NewTokens(%q): %v", app, err)
	}
	return tokens
}

// issueEachTokenType returns one token of every type the issuer can mint.
func issueEachTokenType(t *testing.T, tokens *Tokens) map[string]string {
	t.Helper()
	user := &testUser{ID: "user-1", Name: "Jane", Role: roleViewer}
	access, err := tokens.Generate(user.ID, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	refresh, err := tokens.GenerateRefresh(user.ID, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("GenerateRefresh: %v", err)
	}
	return map[string]string{"access": access, "refresh": refresh}
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
		tokens, err := NewTokens(Config{Key: testJWTKey, AppName: name, AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour})
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

func TestGetAuthTokenRequiresTheExactBearerPrefix(t *testing.T) {
	tests := map[string]string{
		"Bearer abc":        "abc",
		"abc":               "",
		"bearer abc":        "",
		"xBearer abc":       "",
		"Bearer ":           "",
		"":                  "",
		"Bearer a Bearer b": "a Bearer b",
	}
	for header, want := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		if got := GetAuthToken(req); got != want {
			t.Errorf("GetAuthToken(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestClaimsRejectsOtherAlgorithmsAndTokensWithoutExpiry(t *testing.T) {
	tokens := newTestTokens(t)
	for name, method := range map[string]jwt.SigningMethod{"HS512": jwt.SigningMethodHS512, "HS384": jwt.SigningMethodHS384} {
		raw, err := jwt.NewWithClaims(method, jwt.MapClaims{
			"iss": "test-app", "aud": "test-app", "exp": time.Now().Add(time.Hour).Unix(), "token_type": "access",
		}).SignedString([]byte(testJWTKey))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tokens.Claims(raw); err == nil {
			t.Fatalf("%s token must be rejected", name)
		}
	}
	noExp, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "test-app", "aud": "test-app", "token_type": "access",
	}).SignedString([]byte(testJWTKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Claims(noExp); err == nil {
		t.Fatal("a token without exp must be rejected")
	}
}

func TestEveryTokenGetsAUniqueRandomJTI(t *testing.T) {
	tokens := newTestTokens(t)
	seen := map[string]struct{}{}
	for range 5 {
		raw, err := tokens.Generate("u", "n", "viewer", "same-request-id")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := tokens.Claims(raw)
		if err != nil {
			t.Fatal(err)
		}
		jti, _ := claims["jti"].(string)
		if jti == "" || jti == "same-request-id" {
			t.Fatalf("jti = %q", jti)
		}
		seen[jti] = struct{}{}
	}
	if len(seen) != 5 {
		t.Fatalf("jti values repeat: %v", seen)
	}
}

func TestImpersonationTokensLiveAtMostFifteenMinutes(t *testing.T) {
	tokens := newTestTokens(t) // access TTL is longer
	raw, err := tokens.GenerateImpersonated("t", "T", "viewer", "log", "a", "A", "admin")
	if err != nil {
		t.Fatal(err)
	}
	exp, err := tokens.ExpiresAt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if until := time.Until(exp); until > 15*time.Minute+5*time.Second {
		t.Fatalf("impersonation token lives %v", until)
	}
}
