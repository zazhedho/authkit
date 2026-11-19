package middleware

import (
	"context"
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
	live bool
	err  error
}

func (d sessionIndexDouble) HasAccessTokenSession(ctx context.Context, tokenString string) (bool, error) {
	return d.live, d.err
}

func authWith(t *testing.T, users UserStates, cache StateCache, sessions SessionIndex) *Middleware {
	t.Helper()
	mdw := NewMiddleware(&authRepoTestDouble{}, &permissionRepoTestDouble{}, nil, testTokens(t), 2*time.Minute)
	mdw.Users, mdw.StateCache, mdw.Sessions = users, cache, sessions
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
	raw, err := testTokens(t).GenerateImpersonated("user-1", "Jane", domainuser.RoleViewer, "log", "admin-1", "Admin", domainuser.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	rec := performMiddlewareRequest(raw, mdw.AuthMiddleware())
	if rec.Code != http.StatusOK {
		t.Fatalf("impersonation token: status = %d, want 200", rec.Code)
	}
	_ = token.AppClaims{}
}
