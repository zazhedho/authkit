package user

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

func TestSensitiveSelfRoutesAreClosedWhileImpersonating(t *testing.T) {
	scope := domainauth.New("target", "Target", "viewer", nil)
	scope.IsImpersonated = true
	scope.OriginalUserID = "admin"
	handler := newUserHandlerForTest()

	for name, call := range map[string]func(){
		"change password": func() {
			ctx, rec := newUserHandlerTestContext(t, http.MethodPut, "/change/password", `{"current_password":"secret123","new_password":"secret456"}`, &scope)
			handler.ChangePassword(ctx)
			assertUserHandlerStatus(t, rec, http.StatusForbidden)
		},
		"update profile": func() {
			ctx, rec := newUserHandlerTestContext(t, http.MethodPut, "/user", `{"name":"Someone"}`, &scope)
			handler.Update(ctx)
			assertUserHandlerStatus(t, rec, http.StatusForbidden)
		},
		"delete own account": func() {
			ctx, rec := newUserHandlerTestContext(t, http.MethodDelete, "/user", `{"current_password":"secret123"}`, &scope)
			handler.Delete(ctx)
			assertUserHandlerStatus(t, rec, http.StatusForbidden)
		},
	} {
		t.Run(name, func(t *testing.T) { call() })
	}
}

func TestDeleteOwnAccountNeedsTheCurrentPassword(t *testing.T) {
	handler := newUserHandlerForTest()
	handler.Service.(*userServiceTestDouble).err = domainuser.ErrPasswordIncorrect
	scope := domainauth.New("user-1", "Jane", "viewer", nil)
	ctx, rec := newUserHandlerTestContext(t, http.MethodDelete, "/user", `{"current_password":"wrong-pass"}`, &scope)
	handler.Delete(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)
}

func TestRoleRuleErrorsMapToTheRightStatus(t *testing.T) {
	cases := map[error]int{
		domainuser.ErrRoleAboveActor: http.StatusForbidden,
		domainuser.ErrSelfRoleChange: http.StatusForbidden,
		domainuser.ErrLastSuperAdmin: http.StatusConflict,
		domainuser.ErrEmailRequired:  http.StatusBadRequest,
	}
	for err, want := range cases {
		if code, _ := userMutationErrorResponse([16]byte{}, err); code != want {
			t.Errorf("%v: got %d, want %d", err, code, want)
		}
	}
}

func TestLogoutFailsWhenTheSessionCannotBeDestroyed(t *testing.T) {
	handler := newUserHandlerForTest()
	handler.SessionSvc = &sessionServiceUserHandlerTestDouble{destroyTokenErr: errors.New("redis down")}
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/logout", "", nil)
	ctx.Set("token", "access-token")
	handler.Logout(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
}

func TestLogoutTreatsAMissingSessionAsAlreadyGone(t *testing.T) {
	handler := newUserHandlerForTest()
	handler.SessionSvc = &sessionServiceUserHandlerTestDouble{destroyTokenErr: domainsession.ErrNotFound}
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/logout", "", nil)
	ctx.Set("token", "access-token")
	handler.Logout(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
}

func TestLogoutAlsoRevokesTheOwnedRefreshToken(t *testing.T) {
	handler := newUserHandlerForTest()
	refresh, err := testHandlerTokens().GenerateRefresh("user-1", "Jane", "user", "log")
	if err != nil {
		t.Fatal(err)
	}
	scope := domainauth.New("user-1", "Jane", "user", nil)
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/logout", `{"refresh_token":"`+refresh+`"}`, &scope)
	ctx.Set("token", "access-token")
	handler.Logout(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
	if got := handler.Service.(*userServiceTestDouble).logoutTokens; len(got) != 2 || got[0] != refresh {
		t.Fatalf("the refresh token was not blacklisted: %q", got)
	}
}

func TestRefreshRejectsAnAlreadyUsedRefreshToken(t *testing.T) {
	handler := newUserHandlerForTest()
	handler.Service.(*userServiceTestDouble).logoutErr = domainauth.ErrDuplicate
	refresh, err := testHandlerTokens().GenerateRefresh("user-1", "Jane", "user", "log")
	if err != nil {
		t.Fatal(err)
	}
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+refresh+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)
}

func TestFailedLoginCountsPerClientAndPerIdentifier(t *testing.T) {
	limiter := &loginLimiterUserHandlerTestDouble{}
	handler := New(&userServiceTestDouble{loginErr: domainuser.ErrInvalidCredentials}, nil, limiter, nil, testHandlerOptions())
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)
	if len(limiter.registeredKeys) != 2 || limiter.registeredKeys[1] != "identifier:jane@example.com" {
		t.Fatalf("registered keys = %v, want the per-client key and identifier:jane@example.com", limiter.registeredKeys)
	}
}

func TestLoginFailsWhenTheSessionCannotBeStored(t *testing.T) {
	sessions := &sessionServiceUserHandlerTestDouble{createErr: errors.New("redis down")}
	handler := New(&userServiceTestDouble{user: domainuser.Users{ID: "u1", Email: "jane@example.com", Role: "viewer"}}, sessions, nil, nil, testHandlerOptions())
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("tokens must not be returned: %s", rec.Body.String())
	}
}
