package middleware

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
)

type stateDouble struct {
	state domainuser.AuthState
	err   error
	calls int
}

func (d *stateDouble) GetAuthState(ctx context.Context, userID string) (domainuser.AuthState, error) {
	d.calls++
	return d.state, d.err
}

type stateCacheDouble struct {
	states map[string]domainuser.AuthState
	sets   int
}

func (c *stateCacheDouble) GetAuthState(ctx context.Context, userID string) (domainuser.AuthState, bool) {
	s, ok := c.states[userID]
	return s, ok
}

func (c *stateCacheDouble) SetAuthState(ctx context.Context, userID string, s domainuser.AuthState, ttl time.Duration) {
	if c.states == nil {
		c.states = map[string]domainuser.AuthState{}
	}
	c.states[userID] = s
	c.sets++
}

type sessionIndexDouble struct {
	live        bool
	sessionLive bool
	err         error
}

func (d sessionIndexDouble) HasSession(ctx context.Context, id string) (bool, error) {
	return d.sessionLive, d.err
}

func (d sessionIndexDouble) HasAccessTokenSession(ctx context.Context, tokenString string) (bool, error) {
	return d.live, d.err
}

func authWith(t *testing.T, users UserStates, cache StateCache, sessions SessionIndex) *Middleware {
	t.Helper()
	mdw, err := New(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute, users, cache, sessions)
	if err != nil {
		t.Fatal(err)
	}
	return mdw
}

func TestAuthRejectsATokenForAUserWhoNoLongerExists(t *testing.T) {
	mdw := authWith(t, &stateDouble{err: domainuser.ErrNotFound}, nil, nil)
	rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer), mdw.AuthMiddleware())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthRejectsTokensIssuedBeforeTokensValidAfter(t *testing.T) {
	cutoff := time.Now().Add(time.Hour)
	mdw := authWith(t, &stateDouble{state: domainuser.AuthState{Role: domainuser.RoleViewer, TokensValidAfter: &cutoff}}, nil, nil)
	rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer), mdw.AuthMiddleware())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthAcceptsTokensIssuedAfterTokensValidAfter(t *testing.T) {
	cutoff := time.Now().Add(-time.Hour)
	mdw := authWith(t, &stateDouble{state: domainuser.AuthState{Role: domainuser.RoleViewer, TokensValidAfter: &cutoff}}, nil, nil)
	rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer), mdw.AuthMiddleware())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAuthUsesTheCurrentDatabaseRoleNotTheTokenRole(t *testing.T) {
	mdw := authWith(t, &stateDouble{state: domainuser.AuthState{Role: domainuser.RoleViewer}}, nil, nil)
	// The token says superadmin; the database says viewer. RoleMiddleware must
	// see viewer.
	rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleSuperAdmin), mdw.AuthMiddleware(), mdw.RoleMiddleware(domainuser.RoleAdmin))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestAuthCachesTheStateAndStopsHittingTheDatabase(t *testing.T) {
	users := &stateDouble{state: domainuser.AuthState{Role: domainuser.RoleViewer}}
	cache := &stateCacheDouble{}
	mdw := authWith(t, users, cache, nil)
	for range 3 {
		rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer), mdw.AuthMiddleware())
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	}
	if users.calls != 1 || cache.sets != 1 {
		t.Fatalf("db calls = %d cache sets = %d, want 1 and 1", users.calls, cache.sets)
	}
}

func TestAuthRequiresALiveSessionWhenSessionsAreEnabled(t *testing.T) {
	users := &stateDouble{state: domainuser.AuthState{Role: domainuser.RoleViewer}}
	rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer),
		authWith(t, users, nil, sessionIndexDouble{live: false}).AuthMiddleware())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session: status = %d, want 401", rec.Code)
	}
	rec = performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer),
		authWith(t, users, nil, sessionIndexDouble{live: true}).AuthMiddleware())
	if rec.Code != http.StatusOK {
		t.Fatalf("live session: status = %d, want 200", rec.Code)
	}
}

func TestAuthSessionCheckFailureIsAnError(t *testing.T) {
	users := &stateDouble{state: domainuser.AuthState{Role: domainuser.RoleViewer}}
	mdw := authWith(t, users, nil, sessionIndexDouble{err: context.DeadlineExceeded})
	rec := performMiddlewareRequest(testToken(t, "access", domainuser.RoleViewer), mdw.AuthMiddleware())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestAuthSkipsTheSessionCheckForSessionlessTokens(t *testing.T) {
	users := &stateDouble{state: domainuser.AuthState{Role: domainuser.RoleViewer}}
	mdw := authWith(t, users, nil, sessionIndexDouble{live: false})
	raw, err := testTokens(t).GenerateImpersonated("user-1", "Jane", domainuser.RoleViewer, "admin-1", "Admin", domainuser.RoleAdmin, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	rec := performMiddlewareRequest(raw, mdw.AuthMiddleware())
	if rec.Code != http.StatusOK {
		t.Fatalf("impersonation token: status = %d, want 200", rec.Code)
	}
	_ = token.AppClaims{}
}

// claimUsers answers every user lookup with the role of the token it last saw,
// so tests that only care about roles and permissions need no user table.
type claimUsers struct {
	TokenVerifier
	role string
}

func (c *claimUsers) ClaimsFromRequest(r *http.Request) (string, map[string]any, error) {
	raw, claims, err := c.TokenVerifier.ClaimsFromRequest(r)
	if err == nil {
		c.role, _ = claims["role"].(string)
	}
	return raw, claims, err
}

func (c *claimUsers) GetAuthState(context.Context, string) (domainuser.AuthState, error) {
	return domainuser.AuthState{Role: c.role}, nil
}

func newForTest(t *testing.T, blacklist TokenRevocations, perms PermissionLookup, cache PermissionCache, tokens TokenVerifier, ttl time.Duration) *Middleware {
	t.Helper()
	users := &claimUsers{TokenVerifier: tokens}
	mdw, err := New(blacklist, perms, cache, users, ttl, users, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return mdw
}

func TestNewRefusesMissingDependencies(t *testing.T) {
	users := &stateDouble{}
	tokens := testTokens(t)
	cases := map[string]func() (*Middleware, error){
		"users": func() (*Middleware, error) {
			return New(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, tokens, 0, nil, nil, nil)
		},
		"tokens": func() (*Middleware, error) {
			return New(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, nil, 0, users, nil, nil)
		},
		"blacklist": func() (*Middleware, error) {
			return New(nil, &permissionRepoTestDouble{}, nil, tokens, 0, users, nil, nil)
		},
	}
	for name, build := range cases {
		if _, err := build(); !errors.Is(err, ErrMissingDependency) {
			t.Errorf("nil %s: err = %v, want ErrMissingDependency", name, err)
		}
	}
}

func TestAuthRevokesWithMillisecondPrecision(t *testing.T) {
	raw := testToken(t, "access", domainuser.RoleViewer)
	claims, err := testTokens(t).Claims(raw)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.UnixMilli(int64(claims["iat_ms"].(float64)))
	for name, tc := range map[string]struct {
		cutoff time.Time
		want   int
	}{
		"revoked at the issue instant": {issued, http.StatusUnauthorized},
		"revoked just after issue":     {issued.Add(time.Millisecond), http.StatusUnauthorized},
		"revoked just before issue":    {issued.Add(-time.Millisecond), http.StatusOK},
	} {
		mdw := authWith(t, &stateDouble{state: domainuser.AuthState{Role: domainuser.RoleViewer, TokensValidAfter: &tc.cutoff}}, nil, nil)
		if rec := performMiddlewareRequest(raw, mdw.AuthMiddleware()); rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, tc.want)
		}
	}
}

type statesByID map[string]domainuser.AuthState

func (s statesByID) GetAuthState(_ context.Context, id string) (domainuser.AuthState, error) {
	state, ok := s[id]
	if !ok {
		return domainuser.AuthState{}, domainuser.ErrNotFound
	}
	return state, nil
}

func TestImpersonationTokenDiesWithTheOriginalUser(t *testing.T) {
	raw, err := testTokens(t).GenerateImpersonated("target", "T", domainuser.RoleViewer, "admin", "A", domainuser.RoleAdmin, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	for name, tc := range map[string]struct {
		states statesByID
		want   int
	}{
		"both live":                    {statesByID{"target": {Role: "viewer"}, "admin": {Role: "admin"}}, http.StatusOK},
		"original deleted":             {statesByID{"target": {Role: "viewer"}}, http.StatusUnauthorized},
		"original revoked after issue": {statesByID{"target": {Role: "viewer"}, "admin": {Role: "admin", TokensValidAfter: &future}}, http.StatusUnauthorized},
		"target revoked after issue":   {statesByID{"target": {Role: "viewer", TokensValidAfter: &future}, "admin": {Role: "admin"}}, http.StatusUnauthorized},
	} {
		mdw := authWith(t, tc.states, nil, nil)
		if rec := performMiddlewareRequest(raw, mdw.AuthMiddleware()); rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, tc.want)
		}
	}
}

func TestImpersonationEndsWhenTheActorsSessionOrTokenEnds(t *testing.T) {
	raw, err := testTokens(t).GenerateImpersonatedBound("target", "T", domainuser.RoleViewer, "admin", "A", domainuser.RoleAdmin, "sid-1", "hash-1", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	states := statesByID{"target": {Role: "viewer"}, "admin": {Role: "admin"}}
	build := func(blacklist *authRepoTestDouble, sessions SessionIndex) *Middleware {
		mdw, err := New(blacklist, &permissionRepoTestDouble{}, nil, testTokens(t), time.Minute, states, nil, sessions)
		if err != nil {
			t.Fatal(err)
		}
		return mdw
	}
	cases := map[string]struct {
		blacklist *authRepoTestDouble
		sessions  SessionIndex
		want      int
	}{
		"actor session live, token not revoked": {&authRepoTestDouble{}, sessionIndexDouble{sessionLive: true}, http.StatusOK},
		"actor session gone":                    {&authRepoTestDouble{}, sessionIndexDouble{sessionLive: false}, http.StatusUnauthorized},
		"actor access token logged out":         {&authRepoTestDouble{hashes: map[string]bool{"hash-1": true}}, nil, http.StatusUnauthorized},
		"redis off, token not revoked":          {&authRepoTestDouble{}, nil, http.StatusOK},
	}
	for name, tc := range cases {
		if rec := performMiddlewareRequest(raw, build(tc.blacklist, tc.sessions).AuthMiddleware()); rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, tc.want)
		}
	}
}
