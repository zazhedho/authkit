package user

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/google/uuid"
	"github.com/zazhedho/logus"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
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
	refresh, err := testHandlerTokens().GenerateRefresh("user-1", "Jane", "user", time.Time{})
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
	refresh, err := testHandlerTokens().GenerateRefresh("user-1", "Jane", "user", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+refresh+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)
}

func TestFailedLoginCountsPerClientAndPerIdentifier(t *testing.T) {
	limiter, byIdentifier := &loginLimiterUserHandlerTestDouble{}, &loginLimiterUserHandlerTestDouble{}
	opts := testHandlerOptions()
	opts.IdentifierLimiter = byIdentifier
	handler := New(&userServiceTestDouble{loginErr: domainuser.ErrInvalidCredentials}, nil, limiter, nil, opts)
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)
	if len(limiter.registeredKeys) != 1 || !strings.HasSuffix(limiter.registeredKeys[0], ":jane@example.com") ||
		len(byIdentifier.registeredKeys) != 1 || byIdentifier.registeredKeys[0] != "identifier:jane@example.com" {
		t.Fatalf("per-client keys = %v, per-identifier keys = %v", limiter.registeredKeys, byIdentifier.registeredKeys)
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

func TestLoginFailsClosedWhenTheLimiterIsDownAndTheOptionIsOn(t *testing.T) {
	for _, closed := range []bool{false, true} {
		opts := testHandlerOptions()
		opts.Settings.FailClosedLimiters = closed
		handler := New(&userServiceTestDouble{loginErr: domainuser.ErrInvalidCredentials}, nil, &loginLimiterUserHandlerTestDouble{isBlockedErr: errors.New("redis down")}, nil, opts)
		ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
		handler.Login(ctx)
		want := http.StatusBadRequest // fail open: the login runs and fails on credentials
		if closed {
			want = http.StatusServiceUnavailable
		}
		assertUserHandlerStatus(t, rec, want)
	}
}

func TestResetWithAWeakPasswordDoesNotConsumeTheToken(t *testing.T) {
	resets := &resetServiceUserHandlerTestDouble{email: "jane@example.com"}
	handler := New(&userServiceTestDouble{user: domainuser.Users{ID: "u1", Email: "jane@example.com"}}, nil, nil, nil, Options{
		Tokens: testHandlerTokens(), Settings: testUserSettings(), AppConfigService: &appConfigServiceUserTestDouble{enabled: true}, ResetService: resets,
	})
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"weak"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)
	if resets.verified != 0 {
		t.Fatalf("the token was consumed %d times by a request with a weak password", resets.verified)
	}
}

type flakyConfigDouble struct{ err error }

func (f flakyConfigDouble) IsEnabled(context.Context, string, bool) (bool, error) { return true, f.err }

func TestAMalformedFlagValueDoesNotBreakTheAuthRoutes(t *testing.T) {
	opts := testHandlerOptions()
	opts.AppConfigService = flakyConfigDouble{err: fmt.Errorf("%w: boolean expected", domainappconfig.ErrInvalidValue)}
	handler := New(&userServiceTestDouble{}, nil, nil, nil, opts)
	ctx, rec := newUserHandlerTestContext(t, http.MethodGet, "/register/status", "", nil)
	handler.GetRegisterStatus(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	opts.AppConfigService = flakyConfigDouble{err: errors.New("database down")}
	handler = New(&userServiceTestDouble{}, nil, nil, nil, opts)
	ctx, rec = newUserHandlerTestContext(t, http.MethodGet, "/register/status", "", nil)
	handler.GetRegisterStatus(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
}

type failingAudit struct{}

func (failingAudit) Store(context.Context, domainaudit.AuditEvent) error {
	return errors.New("audit down")
}
func (failingAudit) GetAll(context.Context, gokit.BaseParams) ([]dtoaudit.AuditTrailResponse, int64, error) {
	return nil, 0, nil
}
func (failingAudit) GetByID(context.Context, string) (dtoaudit.AuditTrailResponse, error) {
	return dtoaudit.AuditTrailResponse{}, nil
}

func TestImpersonationStartIsNotReleasedWithoutAnAuditRecord(t *testing.T) {
	handler := New(&userServiceTestDouble{}, nil, nil, failingAudit{}, testHandlerOptions())
	target := "550e8400-e29b-41d4-a716-446655440000"
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/users/"+target+"/impersonate", `{"reason":"support case"}`, nil)
	ctx.Params = gin.Params{{Key: "id", Value: target}}
	handler.ImpersonateUser(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("a token was released without an audit record: %s", rec.Body.String())
	}
}

func TestStopImpersonationFailsWhenTheTokenCannotBeRevoked(t *testing.T) {
	scope := domainauth.New("target", "Target", "viewer", nil)
	scope.IsImpersonated = true
	scope.OriginalUserID = "admin"
	handler := New(&userServiceTestDouble{logoutErr: errors.New("blacklist down")}, nil, nil, nil, testHandlerOptions())
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/stop-impersonation", "", &scope)
	ctx.Set("token", "impersonation-token")
	handler.StopImpersonation(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
	if strings.Contains(rec.Body.String(), "restored-token") {
		t.Fatalf("the original identity was handed back with a live impersonation token: %s", rec.Body.String())
	}
}

func TestUserAuditSnapshotIsAnAllowList(t *testing.T) {
	u := domainuser.Users{ID: "1", Name: "N", Email: "e@example.test", Phone: "628", Role: "viewer",
		LastLoginIP: "10.0.0.1", LastLoginUserAgent: "ua", Metadata: map[string]any{"secret": "x"}, Password: "hash"}
	got := userSnapshot(u)
	for _, banned := range []string{"last_login_ip", "last_login_user_agent", "metadata", "password"} {
		if _, ok := got[banned]; ok {
			t.Errorf("snapshot contains %q", banned)
		}
	}
	if len(got) != 5 {
		t.Errorf("snapshot = %v, want id, name, email, phone, role", got)
	}
	upd := updateSnapshot(dtouser.Update{Name: "N", CurrentPassword: "secret"})
	if _, ok := upd["current_password"]; ok {
		t.Error("the update snapshot must not carry the current password")
	}
}

func TestUserResponsesHideLoginBookkeepingFromNonSuperadmins(t *testing.T) {
	u := domainuser.Users{ID: "1", Name: "N", Email: "e@example.test", LastLoginIP: "10.0.0.1", LastLoginUserAgent: "ua", Metadata: map[string]any{"k": "v"}}
	body := func(detailed bool) string {
		raw, _ := json.Marshal(dtouser.NewResponse(u, detailed))
		return string(raw)
	}
	for _, field := range []string{"last_login_ip", "last_login_user_agent", "metadata", "locked_until"} {
		if strings.Contains(body(false), field) {
			t.Errorf("a non-superadmin response contains %s", field)
		}
	}
	for _, field := range []string{"last_login_ip", "last_login_user_agent", "metadata"} {
		if !strings.Contains(body(true), field) {
			t.Errorf("a superadmin response lacks %s", field)
		}
	}
	if strings.Contains(body(true), "locked_until") {
		t.Error("locked_until is gone for everyone")
	}
}

func TestGoogleLoginFailsWhenTheSessionCannotBeStored(t *testing.T) {
	handler := New(&userServiceTestDouble{user: domainuser.Users{ID: "u1", Email: "jane@example.com", Role: "viewer"}}, &sessionServiceUserHandlerTestDouble{createErr: errors.New("redis down")}, nil, nil, testHandlerOptions())
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/google/login", `{"id_token":"abc"}`, nil)
	handler.GoogleLogin(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("tokens must not be returned: %s", rec.Body.String())
	}
}

// The debug request line for an admin update must not carry the password the
// caller supplied.
func TestUpdateUserByIDDebugLogRedactsTheCurrentPassword(t *testing.T) {
	var buf bytes.Buffer
	logus.SetOutput(&buf)
	logus.SetLevel(logus.LevelDebug)
	t.Cleanup(func() { logus.SetOutput(os.Stderr); logus.SetLevel(logus.LevelInfo) })

	handler := newUserHandlerForTest()
	ctx, _ := newUserHandlerTestContext(t, http.MethodPut, "/user/"+uuid.NewString(), `{"name":"Jane Doe","current_password":"Sup3r-Secret!"}`, nil)
	ctx.Params = gin.Params{{Key: "id", Value: uuid.NewString()}}
	handler.UpdateUserByID(ctx)

	if !strings.Contains(buf.String(), "Request:") {
		t.Fatalf("the debug line was not logged:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "Sup3r-Secret!") {
		t.Fatalf("the plaintext password reached the log:\n%s", buf.String())
	}
}

func TestDeleteByIDOfYourOwnAccountNeedsThePasswordAndIsClosedToImpersonators(t *testing.T) {
	id := uuid.NewString()
	call := func(handler *Handler, scope domainauth.Scope, body string) int {
		ctx, rec := newUserHandlerTestContext(t, http.MethodDelete, "/user/"+id, body, &scope)
		ctx.Params = gin.Params{{Key: "id", Value: id}}
		handler.DeleteUserByID(ctx)
		return rec.Code
	}
	own := domainauth.New(id, "Jane", "viewer", nil)

	handler := newUserHandlerForTest()
	if got := call(handler, own, `{}`); got != http.StatusBadRequest {
		t.Fatalf("own id without current_password: %d, want 400", got)
	}
	bad := newUserHandlerForTest()
	bad.Service.(*userServiceTestDouble).err = domainuser.ErrPasswordIncorrect
	if got := call(bad, own, `{"current_password":"wrong-pass"}`); got != http.StatusBadRequest {
		t.Fatalf("own id with a wrong password: %d, want 400", got)
	}
	if got := call(newUserHandlerForTest(), own, `{"current_password":"secret123"}`); got != http.StatusOK {
		t.Fatalf("own id with the password: %d, want 200", got)
	}

	impersonated := own
	impersonated.IsImpersonated, impersonated.OriginalUserID = true, "admin-1"
	if got := call(newUserHandlerForTest(), impersonated, `{"current_password":"secret123"}`); got != http.StatusForbidden {
		t.Fatalf("an impersonator deleting the impersonated account: %d, want 403", got)
	}

	other := domainauth.New("someone-else", "Admin", "admin", nil)
	if got := call(newUserHandlerForTest(), other, ``); got != http.StatusOK {
		t.Fatalf("another user's id needs no password: %d, want 200", got)
	}
}

func TestStopImpersonationRequiresTheActorsSessionToBeLive(t *testing.T) {
	raw, err := testHandlerTokens().GenerateImpersonatedBound("target-1", "T", "viewer", dtoshared.ImpersonationClaims{
		OriginalUserID: "admin-1", OriginalUsername: "A", OriginalRole: "admin", ActorSessionID: "sid-1",
	}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := testHandlerTokens().Claims(raw)
	for name, tc := range map[string]struct {
		err  error
		want int
	}{"session live": {nil, http.StatusOK}, "session gone": {domainsession.ErrNotFound, http.StatusUnauthorized}} {
		handler := newUserHandlerForTest()
		handler.SessionSvc = &sessionServiceUserHandlerTestDouble{sessionIDErr: tc.err}
		scope := domainauth.NewFromClaims(claims, nil)
		ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/user/stop-impersonation", "", &scope)
		ctx.Request = ctx.Request.WithContext(httpshared.WithAuthData(ctx.Request.Context(), claims))
		handler.StopImpersonation(ctx)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", name, rec.Code, tc.want, rec.Body.String())
		}
	}
}
