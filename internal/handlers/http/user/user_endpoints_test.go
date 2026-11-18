package user

import (
	"context"
	"encoding/json"
	"errors"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainotp "github.com/zazhedho/authkit/internal/domain/otp"
	domainreset "github.com/zazhedho/authkit/internal/domain/reset"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type userServiceTestDouble struct {
	user        domainuser.Users
	err         error
	googleErr   error
	loginErr    error
	logoutToken string
	revoked     bool
	revokedErr  error
}

func (s *userServiceTestDouble) RegisterUser(ctx context.Context, req dtouser.UserRegister) (domainuser.Users, error) {
	if s.err != nil {
		return domainuser.Users{}, s.err
	}
	s.user.Name = req.Name
	s.user.Email = req.Email
	s.user.Phone = req.Phone
	return s.user, nil
}
func (s *userServiceTestDouble) AdminCreateUser(ctx context.Context, actor domainauth.Actor, req dtouser.AdminCreateUser) (domainuser.Users, error) {
	if s.err != nil {
		return domainuser.Users{}, s.err
	}
	s.user.Name = req.Name
	s.user.Email = req.Email
	s.user.Phone = req.Phone
	s.user.Role = req.Role
	return s.user, nil
}
func (s *userServiceTestDouble) LoginUser(ctx context.Context, req dtouser.Login, logId string, metadata dtouser.LoginMetadata) (string, error) {
	if s.loginErr != nil {
		return "", s.loginErr
	}
	if s.err != nil {
		return "", s.err
	}
	return "access-token", nil
}
func (s *userServiceTestDouble) LoginWithGoogle(ctx context.Context, req dtouser.GoogleLogin, metadata dtouser.LoginMetadata, allowRegistration bool) (domainuser.Users, bool, error) {
	if s.googleErr != nil {
		return domainuser.Users{}, false, s.googleErr
	}
	if s.err != nil {
		return domainuser.Users{}, false, s.err
	}
	return s.user, false, nil
}
func (s *userServiceTestDouble) LogoutUser(ctx context.Context, token string) error {
	s.logoutToken = token
	return s.err
}
func (s *userServiceTestDouble) ImpersonateUser(ctx context.Context, actor domainauth.Actor, targetUserId string, logId string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "impersonation-token", nil
}
func (s *userServiceTestDouble) StopImpersonation(ctx context.Context, actor domainauth.Actor, logId string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "restored-token", nil
}
func (s *userServiceTestDouble) GetUserById(ctx context.Context, id string) (domainuser.Users, error) {
	if s.err != nil {
		return domainuser.Users{}, s.err
	}
	s.user.Id = id
	return s.user, nil
}
func (s *userServiceTestDouble) GetUserByEmail(ctx context.Context, email string) (domainuser.Users, error) {
	if s.err != nil {
		return domainuser.Users{}, s.err
	}
	if s.user.Email == email {
		return s.user, nil
	}
	return domainuser.Users{}, nil
}
func (s *userServiceTestDouble) GetUserByPhone(ctx context.Context, phone string) (domainuser.Users, error) {
	if s.err != nil {
		return domainuser.Users{}, s.err
	}
	return s.user, nil
}
func (s *userServiceTestDouble) GetUserByAuth(ctx context.Context, id string) (map[string]any, error) {
	if s.err != nil {
		return nil, s.err
	}
	return map[string]any{"id": id, "name": s.user.Name, "role": s.user.Role}, nil
}
func (s *userServiceTestDouble) GetAllUsers(ctx context.Context, actor domainauth.Actor, req dtoshared.ListRequest) ([]domainuser.Users, int64, error) {
	if s.err != nil {
		return nil, 0, s.err
	}
	return []domainuser.Users{s.user}, 1, nil
}
func (s *userServiceTestDouble) Update(ctx context.Context, actor domainauth.Actor, id string, req dtouser.UserUpdate) (domainuser.Users, error) {
	if s.err != nil {
		return domainuser.Users{}, s.err
	}
	s.user.Id = id
	if req.Name != "" {
		s.user.Name = req.Name
	}
	if req.Email != "" {
		s.user.Email = req.Email
	}
	if req.Phone != "" {
		s.user.Phone = req.Phone
	}
	if req.Role != "" {
		s.user.Role = req.Role
	}
	return s.user, nil
}
func (s *userServiceTestDouble) ChangePassword(ctx context.Context, id string, req dtouser.ChangePassword) (domainuser.Users, error) {
	if s.err != nil {
		return domainuser.Users{}, s.err
	}
	s.user.Id = id
	return s.user, nil
}
func (s *userServiceTestDouble) ForgotPassword(ctx context.Context, req dtouser.ForgotPasswordRequest) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "reset-token", nil
}
func (s *userServiceTestDouble) ResetPassword(ctx context.Context, req dtouser.ResetPasswordRequest) error {
	return s.err
}
func (s *userServiceTestDouble) ResetPasswordByEmail(ctx context.Context, email, newPassword string) error {
	return s.err
}
func (s *userServiceTestDouble) Delete(ctx context.Context, id string) error {
	return s.err
}
func (s *userServiceTestDouble) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
	if s.revokedErr != nil {
		return false, s.revokedErr
	}
	return s.revoked, nil
}

type otpServiceUserHandlerTestDouble struct {
	sentEmail     string
	sentAppName   string
	verifiedEmail string
	err           error
}

func (m *otpServiceUserHandlerTestDouble) SendRegisterOTP(ctx context.Context, email, appName string) error {
	if m.err != nil {
		return m.err
	}
	m.sentEmail = email
	m.sentAppName = appName
	return nil
}
func (m *otpServiceUserHandlerTestDouble) VerifyRegisterOTP(ctx context.Context, email, code string) error {
	if m.err != nil {
		return m.err
	}
	m.verifiedEmail = email
	return nil
}

type sessionServiceUserHandlerTestDouble struct {
	sessionID       string
	createErr       error
	refreshErr      error
	rotateErr       error
	destroyTokenErr error
	destroyAllErr   error
	destroyedUserID string
	rotatedAccess   string
	rotatedRefresh  string
	rotatedExpiry   time.Time
}

func (m *sessionServiceUserHandlerTestDouble) CreateSession(ctx context.Context, user *domainuser.Users, accessToken string, refreshToken string, requestMeta domainsession.RequestMeta) (*domainsession.Session, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	m.sessionID = "session-1"
	return &domainsession.Session{SessionID: m.sessionID, UserID: user.Id, AccessToken: accessToken, RefreshToken: refreshToken, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (m *sessionServiceUserHandlerTestDouble) GetUserSessions(ctx context.Context, userID string, currentSessionID string) ([]*domainsession.SessionInfo, error) {
	return nil, nil
}
func (m *sessionServiceUserHandlerTestDouble) DestroySession(ctx context.Context, sessionID string) error {
	return nil
}
func (m *sessionServiceUserHandlerTestDouble) DestroySessionByToken(ctx context.Context, token string) error {
	if m.destroyTokenErr != nil {
		return m.destroyTokenErr
	}
	return nil
}
func (m *sessionServiceUserHandlerTestDouble) DestroyAllUserSessions(ctx context.Context, userID string) error {
	if m.destroyAllErr != nil {
		return m.destroyAllErr
	}
	m.destroyedUserID = userID
	return nil
}
func (m *sessionServiceUserHandlerTestDouble) DestroyOtherSessions(ctx context.Context, userID string, currentSessionID string) error {
	return nil
}
func (m *sessionServiceUserHandlerTestDouble) GetSessionByToken(ctx context.Context, token string) (*domainsession.Session, error) {
	return &domainsession.Session{SessionID: "session-1"}, nil
}
func (m *sessionServiceUserHandlerTestDouble) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*domainsession.Session, error) {
	if m.refreshErr != nil {
		return nil, m.refreshErr
	}
	return &domainsession.Session{SessionID: "session-1", RefreshToken: refreshToken}, nil
}
func (m *sessionServiceUserHandlerTestDouble) GetSessionBySessionID(ctx context.Context, sessionID string) (*domainsession.Session, error) {
	return &domainsession.Session{SessionID: sessionID}, nil
}
func (m *sessionServiceUserHandlerTestDouble) RotateSessionTokens(ctx context.Context, sessionID string, accessToken string, refreshToken string, expiresAt time.Time) error {
	if m.rotateErr != nil {
		return m.rotateErr
	}
	m.sessionID = sessionID
	m.rotatedAccess = accessToken
	m.rotatedRefresh = refreshToken
	m.rotatedExpiry = expiresAt
	return nil
}

type loginLimiterUserHandlerTestDouble struct {
	blocked         bool
	ttl             time.Duration
	isBlockedErr    error
	registerBlocked bool
	registerErr     error
	resetErr        error
	registeredKey   string
	resetKey        string
}

func (m *loginLimiterUserHandlerTestDouble) IsBlocked(ctx context.Context, key string) (bool, time.Duration, error) {
	return m.blocked, m.ttl, m.isBlockedErr
}

func (m *loginLimiterUserHandlerTestDouble) RegisterFailure(ctx context.Context, key string) (bool, time.Duration, error) {
	m.registeredKey = key
	return m.registerBlocked, m.ttl, m.registerErr
}

func (m *loginLimiterUserHandlerTestDouble) Reset(ctx context.Context, key string) error {
	m.resetKey = key
	return m.resetErr
}

type resetServiceUserHandlerTestDouble struct {
	email string
	err   error
}

func (m *resetServiceUserHandlerTestDouble) RequestReset(ctx context.Context, email, appName string) error {
	return m.err
}

func (m *resetServiceUserHandlerTestDouble) VerifyReset(ctx context.Context, token string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if m.email == "" {
		return "jane@example.com", nil
	}
	return m.email, nil
}

func newUserHandlerTestContext(t *testing.T, method, path, body string, scope *domainauth.Scope) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if scope != nil {
		req = req.WithContext(domainauth.WithContext(req.Context(), *scope))
	}
	ctx.Request = req
	return ctx, rec
}

func newUserHandlerForTest() *Handler {
	service := &userServiceTestDouble{user: domainuser.Users{
		Id:    "user-1",
		Name:  "Jane Doe",
		Email: "jane@example.com",
		Phone: "628123456789",
		Role:  "user",
	}}
	return New(service, nil, nil, nil, testHandlerOptions())
}

func assertUserHandlerStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("expected status %d, got %d body=%s", want, rec.Code, rec.Body.String())
	}
}

func TestNewUserHandlerWiresDependencies(t *testing.T) {
	service := &userServiceTestDouble{}
	handler := New(service, nil, nil, nil, testHandlerOptions())
	if handler.Service != service {
		t.Fatal("expected service to be assigned")
	}
}

func TestUserHandlerPublicAndAdminFlows(t *testing.T) {
	handler := newUserHandlerForTest()

	ctx, rec := newUserHandlerTestContext(t, http.MethodGet, "/register/status", "", nil)
	handler.GetRegisterStatus(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusCreated)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/admin/users", `{"name":"Admin User","email":"admin@example.com","phone":"628123456780","password":"secret123","role":"admin"}`, nil)
	handler.AdminCreateUser(ctx)
	assertUserHandlerStatus(t, rec, http.StatusCreated)

	ctx, rec = newUserHandlerTestContext(t, http.MethodGet, "/users?page=1&limit=10&role=user", "", nil)
	handler.GetAllUsers(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
}

func TestUserHandlerGetRegisterStatusIncludesOTPConfig(t *testing.T) {
	handler := newUserHandlerForTest()
	handler.Settings.OTPCooldown = 45 * time.Second
	handler.AppConfigService = &appConfigServiceUserTestDouble{enabled: true}

	ctx, rec := newUserHandlerTestContext(t, http.MethodGet, "/register/status", "", nil)
	handler.GetRegisterStatus(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	var body struct {
		Data struct {
			Enabled     bool `json:"enabled"`
			OTPEnabled  bool `json:"otp_enabled"`
			OTPCooldown int  `json:"otp_cooldown"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !body.Data.Enabled || !body.Data.OTPEnabled || body.Data.OTPCooldown != 45 {
		t.Fatalf("unexpected register status payload: %+v", body.Data)
	}
}

func TestUserHandlerAuthTokenFlows(t *testing.T) {
	handler := newUserHandlerForTest()
	sessionSvc := &sessionServiceUserHandlerTestDouble{}
	handler.SessionSvc = sessionSvc
	userSvc := handler.Service.(*userServiceTestDouble)

	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/google/login", `{"id_token":"google-token"}`, nil)
	handler.GoogleLogin(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	user := domainuser.Users{Id: "user-1", Name: "Jane Doe", Email: "jane@example.com", Role: "user"}
	refreshToken, err := testHandlerTokens().GenerateRefresh(user.Id, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+refreshToken+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
	if userSvc.logoutToken != refreshToken {
		t.Fatalf("expected old refresh token to be blacklisted, got %q", userSvc.logoutToken)
	}
	if sessionSvc.rotatedAccess == "" || sessionSvc.rotatedRefresh == "" || sessionSvc.rotatedExpiry.IsZero() {
		t.Fatalf("expected session tokens to be rotated, got access=%q refresh=%q expiry=%v", sessionSvc.rotatedAccess, sessionSvc.rotatedRefresh, sessionSvc.rotatedExpiry)
	}
}

func TestUserHandlerRegisterOTPAndStopImpersonationFlows(t *testing.T) {
	otpService := &otpServiceUserHandlerTestDouble{}
	handler := newUserHandlerForTest()
	handler.AppConfigService = &appConfigServiceUserTestDouble{enabled: true}
	handler.OTPService = otpService

	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
	if otpService.sentEmail != "new@example.com" {
		t.Fatalf("expected normalized OTP email, got %q", otpService.sentEmail)
	}

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123","otp_code":"123456"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusCreated)
	if otpService.verifiedEmail != "new@example.com" {
		t.Fatalf("expected register OTP verification, got %q", otpService.verifiedEmail)
	}

	scope := domainauth.New("target-1", "Target User", "viewer", nil)
	scope.IsImpersonated = true
	scope.OriginalUserID = "admin-1"
	scope.OriginalUsername = "Admin User"
	scope.OriginalRole = "admin"
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/stop-impersonation", "", &scope)
	ctx.Set("token", "impersonation-token")
	handler.StopImpersonation(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
}

func TestUserHandlerReadUpdateAndDeleteFlows(t *testing.T) {
	handler := newUserHandlerForTest()
	userID := uuid.NewString()
	scope := domainauth.New(userID, "Jane Doe", "user", nil)

	ctx, rec := newUserHandlerTestContext(t, http.MethodGet, "/users/"+userID, "", nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.GetUserById(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodGet, "/me", "", &scope)
	handler.GetUserByAuth(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/me", `{"name":"Jane Updated"}`, &scope)
	handler.Update(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/users/"+userID, `{"role":"admin"}`, nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.UpdateUserById(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/me/password", `{"current_password":"secret123","new_password":"secret456"}`, &scope)
	handler.ChangePassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodDelete, "/me", "", &scope)
	handler.Delete(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodDelete, "/users/"+userID, "", nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.DeleteUserById(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
}

func TestUserHandlerPasswordAndSessionFlows(t *testing.T) {
	handler := newUserHandlerForTest()
	handler.Settings.DevEnv = true
	userID := uuid.NewString()

	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/forgot-password", `{"email":"jane@example.com"}`, nil)
	handler.ForgotPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/logout", "", nil)
	ctx.Set("token", "access-token")
	handler.Logout(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/users/"+userID+"/impersonate", "", nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.ImpersonateUser(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
}

func TestUserHandlerUnauthorizedSelfServiceBranches(t *testing.T) {
	handler := newUserHandlerForTest()

	ctx, rec := newUserHandlerTestContext(t, http.MethodGet, "/me", "", nil)
	handler.GetUserByAuth(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/me", `{"name":"Jane"}`, nil)
	handler.Update(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPatch, "/me/password", `{"current_password":"secret123","new_password":"secret456"}`, nil)
	handler.ChangePassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	ctx, rec = newUserHandlerTestContext(t, http.MethodDelete, "/me", "", nil)
	handler.Delete(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)
}

func TestUserHandlerBadJSONBranches(t *testing.T) {
	handler := newUserHandlerForTest()
	handler.AppConfigService = &appConfigServiceUserTestDouble{enabled: true}
	userID := uuid.NewString()
	scope := domainauth.New(userID, "Jane Doe", "user", nil)

	tests := []struct {
		name   string
		method string
		path   string
		scope  *domainauth.Scope
		call   func(*gin.Context)
	}{
		{name: "register", method: http.MethodPost, path: "/register", call: handler.Register},
		{name: "send register otp", method: http.MethodPost, path: "/register/otp/send", call: handler.SendRegisterOTP},
		{name: "admin create", method: http.MethodPost, path: "/admin/users", call: handler.AdminCreateUser},
		{name: "login", method: http.MethodPost, path: "/login", call: handler.Login},
		{name: "google login", method: http.MethodPost, path: "/google/login", call: handler.GoogleLogin},
		{name: "refresh token", method: http.MethodPost, path: "/refresh-token", call: handler.RefreshToken},
		{name: "update self", method: http.MethodPatch, path: "/me", scope: &scope, call: handler.Update},
		{name: "update by id", method: http.MethodPatch, path: "/users/" + userID, call: handler.UpdateUserById},
		{name: "change password", method: http.MethodPatch, path: "/me/password", scope: &scope, call: handler.ChangePassword},
		{name: "forgot password", method: http.MethodPost, path: "/forgot-password", call: handler.ForgotPassword},
		{name: "reset password", method: http.MethodPost, path: "/reset-password", call: handler.ResetPassword},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, rec := newUserHandlerTestContext(t, tt.method, tt.path, `{`, tt.scope)
			if tt.name == "update by id" {
				ctx.Params = gin.Params{{Key: "id", Value: userID}}
			}
			tt.call(ctx)
			assertUserHandlerStatus(t, rec, http.StatusBadRequest)
		})
	}
}

func TestUserHandlerInvalidIDBranches(t *testing.T) {
	handler := newUserHandlerForTest()

	tests := []struct {
		name string
		call func(*gin.Context)
	}{
		{name: "get by id", call: handler.GetUserById},
		{name: "update by id", call: handler.UpdateUserById},
		{name: "delete by id", call: handler.DeleteUserById},
		{name: "impersonate", call: handler.ImpersonateUser},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/users/not-a-uuid", `{"name":"Jane"}`, nil)
			ctx.Params = gin.Params{{Key: "id", Value: "not-a-uuid"}}
			tt.call(ctx)
			assertUserHandlerStatus(t, rec, http.StatusBadRequest)
		})
	}
}

func TestUserHandlerRegistrationConfigBranches(t *testing.T) {
	handler := newUserHandlerForTest()

	handler.AppConfigService = &appConfigServiceUserTestDouble{enabled: false}
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusForbidden)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusForbidden)

	handler.AppConfigService = &appConfigServiceUserTestDouble{err: context.Canceled}
	ctx, rec = newUserHandlerTestContext(t, http.MethodGet, "/register/status", "", nil)
	handler.GetRegisterStatus(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
}

func TestUserHandlerServiceErrorBranches(t *testing.T) {
	userID := uuid.NewString()
	scope := domainauth.New(userID, "Jane Doe", "user", nil)
	service := &userServiceTestDouble{
		user: domainuser.Users{
			Id:    userID,
			Name:  "Jane Doe",
			Email: "jane@example.com",
			Phone: "628123456789",
			Role:  "user",
		},
		err: errors.New("database down"),
	}
	handler := New(service, nil, nil, nil, testHandlerOptions())
	handler.Settings.DevEnv = true

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		scope  *domainauth.Scope
		params gin.Params
		call   func(*gin.Context)
		want   int
	}{
		{name: "register", method: http.MethodPost, path: "/register", body: `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123"}`, call: handler.Register, want: http.StatusInternalServerError},
		{name: "admin create", method: http.MethodPost, path: "/admin/users", body: `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123","role":"user"}`, call: handler.AdminCreateUser, want: http.StatusInternalServerError},
		{name: "get all users", method: http.MethodGet, path: "/users", call: handler.GetAllUsers, want: http.StatusInternalServerError},
		{name: "get user by id", method: http.MethodGet, path: "/users/" + userID, params: gin.Params{{Key: "id", Value: userID}}, call: handler.GetUserById, want: http.StatusInternalServerError},
		{name: "get user by auth", method: http.MethodGet, path: "/me", scope: &scope, call: handler.GetUserByAuth, want: http.StatusInternalServerError},
		{name: "update self", method: http.MethodPatch, path: "/me", body: `{"name":"Jane"}`, scope: &scope, call: handler.Update, want: http.StatusInternalServerError},
		{name: "update by id", method: http.MethodPatch, path: "/users/" + userID, body: `{"name":"Jane"}`, params: gin.Params{{Key: "id", Value: userID}}, call: handler.UpdateUserById, want: http.StatusInternalServerError},
		{name: "change password", method: http.MethodPatch, path: "/me/password", body: `{"current_password":"secret123","new_password":"secret456"}`, scope: &scope, call: handler.ChangePassword, want: http.StatusInternalServerError},
		{name: "delete self", method: http.MethodDelete, path: "/me", scope: &scope, call: handler.Delete, want: http.StatusInternalServerError},
		{name: "delete by id", method: http.MethodDelete, path: "/users/" + userID, params: gin.Params{{Key: "id", Value: userID}}, call: handler.DeleteUserById, want: http.StatusInternalServerError},
		{name: "forgot password", method: http.MethodPost, path: "/forgot-password", body: `{"email":"jane@example.com"}`, call: handler.ForgotPassword, want: http.StatusInternalServerError},
		{name: "reset password", method: http.MethodPost, path: "/reset-password", body: `{"token":"reset-token","new_password":"secret456"}`, call: handler.ResetPassword, want: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, rec := newUserHandlerTestContext(t, tt.method, tt.path, tt.body, tt.scope)
			ctx.Params = tt.params
			tt.call(ctx)
			assertUserHandlerStatus(t, rec, tt.want)
		})
	}
}

func TestUserHandlerAuthErrorBranches(t *testing.T) {

	handler := newUserHandlerForTest()
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/login", `{"password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"not-an-email@","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"12","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	handler.LoginLimiter = &loginLimiterUserHandlerTestDouble{blocked: true, ttl: time.Minute}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusTooManyRequests)

	handler = New(&userServiceTestDouble{loginErr: errors.New(ErrHashPassword)}, nil, nil, nil, testHandlerOptions())
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	handler = New(&userServiceTestDouble{loginErr: domainuser.ErrNotFound}, nil, &loginLimiterUserHandlerTestDouble{registerBlocked: true, ttl: time.Minute}, nil, testHandlerOptions())
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusTooManyRequests)

	handler = New(&userServiceTestDouble{loginErr: errors.New("database down")}, nil, &loginLimiterUserHandlerTestDouble{isBlockedErr: errors.New("redis down")}, nil, testHandlerOptions())
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/login", `{"identifier":"jane@example.com","password":"secret123"}`, nil)
	handler.Login(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)

	handler = New(&userServiceTestDouble{googleErr: domainuser.ErrGoogleNotConfigured}, nil, nil, nil, testHandlerOptions())
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/google/login", `{"id_token":"token"}`, nil)
	handler.GoogleLogin(ctx)
	assertUserHandlerStatus(t, rec, http.StatusServiceUnavailable)

	handler = newUserHandlerForTest()
	handler.Service.(*userServiceTestDouble).revoked = true
	user := domainuser.Users{Id: "user-1", Name: "Jane Doe", Email: "jane@example.com", Role: "user"}
	refreshToken, err := testHandlerTokens().GenerateRefresh(user.Id, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+refreshToken+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	accessToken, err := testHandlerTokens().Generate(user.Id, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+accessToken+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	handler = newUserHandlerForTest()
	handler.Service.(*userServiceTestDouble).revokedErr = errors.New("redis down")
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+refreshToken+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)

	handler = New(&userServiceTestDouble{err: domainuser.ErrNotFound}, nil, nil, nil, testHandlerOptions())
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+refreshToken+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusNotFound)

	handler = newUserHandlerForTest()
	handler.SessionSvc = &sessionServiceUserHandlerTestDouble{refreshErr: errors.New("session missing")}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+refreshToken+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusUnauthorized)

	handler.SessionSvc = &sessionServiceUserHandlerTestDouble{rotateErr: errors.New("rotate failed")}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+refreshToken+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)

	handler = newUserHandlerForTest()
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/logout", "", nil)
	handler.Logout(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
}

func TestUserHandlerOTPErrorBranches(t *testing.T) {
	handler := newUserHandlerForTest()
	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	handler.AppConfigService = &appConfigServiceUserTestDouble{enabled: true}

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123","otp_code":"123456"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusServiceUnavailable)

	handler.OTPService = &otpServiceUserHandlerTestDouble{err: domainotp.ErrTooManyAttempt}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123","otp_code":"123456"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	handler.OTPService = &otpServiceUserHandlerTestDouble{err: domainotp.ErrNotConfigured}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register", `{"name":"Jane Doe","email":"new@example.com","phone":"628123456789","password":"secret123","otp_code":"123456"}`, nil)
	handler.Register(ctx)
	assertUserHandlerStatus(t, rec, http.StatusServiceUnavailable)

	handler.OTPService = &otpServiceUserHandlerTestDouble{}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"jane@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	handler.OTPService = nil
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusServiceUnavailable)

	handler.OTPService = &otpServiceUserHandlerTestDouble{err: &domainotp.ThrottleError{Reason: "rate_limit", RetryAfter: time.Second}}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusTooManyRequests)

	handler.OTPService = &otpServiceUserHandlerTestDouble{err: domainotp.ErrDeliveryFailed}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusServiceUnavailable)

	handler.OTPService = &otpServiceUserHandlerTestDouble{err: errors.New("redis down")}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)
}

func TestUserHandlerNotFoundAndValidationErrorBranches(t *testing.T) {
	userID := uuid.NewString()
	scope := domainauth.New(userID, "Jane Doe", "user", nil)
	handler := New(&userServiceTestDouble{err: domainuser.ErrNotFound}, nil, nil, nil, testHandlerOptions())

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		scope  *domainauth.Scope
		params gin.Params
		call   func(*gin.Context)
		want   int
	}{
		{name: "get user by id", method: http.MethodGet, path: "/users/" + userID, params: gin.Params{{Key: "id", Value: userID}}, call: handler.GetUserById, want: http.StatusNotFound},
		{name: "get user by auth", method: http.MethodGet, path: "/me", scope: &scope, call: handler.GetUserByAuth, want: http.StatusNotFound},
		{name: "update self", method: http.MethodPatch, path: "/me", body: `{"name":"Jane"}`, scope: &scope, call: handler.Update, want: http.StatusNotFound},
		{name: "update by id", method: http.MethodPatch, path: "/users/" + userID, body: `{"name":"Jane"}`, params: gin.Params{{Key: "id", Value: userID}}, call: handler.UpdateUserById, want: http.StatusNotFound},
		{name: "change password", method: http.MethodPatch, path: "/me/password", body: `{"current_password":"secret123","new_password":"secret456"}`, scope: &scope, call: handler.ChangePassword, want: http.StatusNotFound},
		{name: "delete self", method: http.MethodDelete, path: "/me", scope: &scope, call: handler.Delete, want: http.StatusNotFound},
		{name: "delete by id", method: http.MethodDelete, path: "/users/" + userID, params: gin.Params{{Key: "id", Value: userID}}, call: handler.DeleteUserById, want: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, rec := newUserHandlerTestContext(t, tt.method, tt.path, tt.body, tt.scope)
			ctx.Params = tt.params
			tt.call(ctx)
			assertUserHandlerStatus(t, rec, tt.want)
		})
	}

	handler = New(&userServiceTestDouble{err: errors.New(ErrHashPassword)}, nil, nil, nil, testHandlerOptions())
	ctx, rec := newUserHandlerTestContext(t, http.MethodPatch, "/me/password", `{"current_password":"bad","new_password":"secret456"}`, &scope)
	handler.ChangePassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	handler = New(&userServiceTestDouble{err: errors.New("cannot impersonate superadmin users")}, nil, nil, nil, testHandlerOptions())
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/users/"+userID+"/impersonate", "", nil)
	ctx.Params = gin.Params{{Key: "id", Value: userID}}
	handler.ImpersonateUser(ctx)
	assertUserHandlerStatus(t, rec, http.StatusForbidden)

	handler = New(&userServiceTestDouble{err: errors.New("database down")}, nil, nil, nil, testHandlerOptions())
	impersonated := domainauth.New("target-1", "Target", "viewer", nil)
	impersonated.IsImpersonated = true
	impersonated.OriginalUserID = "admin-1"
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/stop-impersonation", "", &impersonated)
	handler.StopImpersonation(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)

	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/stop-impersonation", "", new(domainauth.New("user-1", "Jane", "viewer", nil)))
	handler.StopImpersonation(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)
}

func TestUserHandlerEmailPasswordResetBranches(t *testing.T) {
	handler := newUserHandlerForTest()
	handler.Settings.ResetCooldown = 2 * time.Minute
	handler.AppConfigService = &appConfigServiceUserTestDouble{enabled: true}

	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/forgot-password", `{"email":"jane@example.com"}`, nil)
	handler.ForgotPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusServiceUnavailable)

	handler.ResetService = &resetServiceUserHandlerTestDouble{}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/forgot-password", `{"email":"jane@example.com"}`, nil)
	handler.ForgotPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"cooldown":120`) {
		t.Fatalf("expected reset cooldown in response, body=%s", rec.Body.String())
	}

	handler.ResetService = &resetServiceUserHandlerTestDouble{err: &domainreset.ThrottleError{Reason: "rate_limit", RetryAfter: time.Second}}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/forgot-password", `{"email":"jane@example.com"}`, nil)
	handler.ForgotPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusTooManyRequests)

	handler.ResetService = &resetServiceUserHandlerTestDouble{err: domainreset.ErrDeliveryFailed}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/forgot-password", `{"email":"jane@example.com"}`, nil)
	handler.ForgotPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusServiceUnavailable)

	handler.ResetService = nil
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusServiceUnavailable)

	handler.ResetService = &resetServiceUserHandlerTestDouble{err: domainreset.ErrInvalid}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)

	handler.ResetService = &resetServiceUserHandlerTestDouble{email: "jane@example.com"}
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	handler = New(&userServiceTestDouble{err: domainuser.ErrDuplicate}, nil, nil, nil, Options{Tokens: testHandlerTokens(), Settings: testUserSettings(), AppConfigService: &appConfigServiceUserTestDouble{enabled: true}, ResetService: &resetServiceUserHandlerTestDouble{email: "jane@example.com"}})
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusBadRequest)
}

func TestUserHandlerResetPasswordRevokesSessions(t *testing.T) {

	user := domainuser.Users{Id: "user-1", Email: "jane@example.com", Role: domainuser.RoleViewer}
	service := &userServiceTestDouble{user: user}
	sessionSvc := &sessionServiceUserHandlerTestDouble{}
	handler := New(service, sessionSvc, nil, nil, Options{Tokens: testHandlerTokens(), Settings: testUserSettings(), AppConfigService: &appConfigServiceUserTestDouble{enabled: true}, ResetService: &resetServiceUserHandlerTestDouble{email: user.Email}})

	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
	if sessionSvc.destroyedUserID != user.Id {
		t.Fatalf("expected email reset to revoke sessions for %q, got %q", user.Id, sessionSvc.destroyedUserID)
	}

	handler = New(service, &sessionServiceUserHandlerTestDouble{destroyAllErr: errors.New("session revoke failed")}, nil, nil, Options{Tokens: testHandlerTokens(), Settings: testUserSettings(), AppConfigService: &appConfigServiceUserTestDouble{enabled: true}, ResetService: &resetServiceUserHandlerTestDouble{email: user.Email}})
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"reset-token","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusInternalServerError)

	token, err := testHandlerTokens().Generate(user.Id, user.Name, user.Role, "reset_password")
	if err != nil {
		t.Fatalf("generate reset token: %v", err)
	}
	sessionSvc = &sessionServiceUserHandlerTestDouble{}
	handler = New(service, sessionSvc, nil, nil, Options{Tokens: testHandlerTokens(), Settings: testUserSettings(), AppConfigService: &appConfigServiceUserTestDouble{enabled: false}})
	ctx, rec = newUserHandlerTestContext(t, http.MethodPost, "/reset-password", `{"token":"`+token+`","new_password":"secret456"}`, nil)
	handler.ResetPassword(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)
	if sessionSvc.destroyedUserID != user.Id {
		t.Fatalf("expected jwt reset to revoke sessions for %q, got %q", user.Id, sessionSvc.destroyedUserID)
	}
}

func testHandlerTokens() *token.Tokens {
	tokens, err := token.NewTokens(token.TokenConfig{
		Key:        "test-secret-must-be-at-least-32-bytes",
		AppName:    "test-app",
		AccessTTL:  time.Hour,
		RefreshTTL: 2 * time.Hour,
		ResetTTL:   15 * time.Minute,
	})
	if err != nil {
		panic(err)
	}
	return tokens
}

func testUserSettings() Settings {
	return Settings{EmailAppName: "test-app", AccessTTL: time.Hour, RefreshTTL: time.Hour}
}

func testHandlerOptions() Options {
	return Options{Tokens: testHandlerTokens(), Settings: testUserSettings()}
}

func otherAppTokens() *token.Tokens {
	tokens, err := token.NewTokens(token.TokenConfig{
		Key:        "test-secret-must-be-at-least-32-bytes",
		AppName:    "other-app",
		AccessTTL:  time.Hour,
		RefreshTTL: 2 * time.Hour,
		ResetTTL:   15 * time.Minute,
	})
	if err != nil {
		panic(err)
	}
	return tokens
}

// errorBodyWithoutLogID decodes a response and drops the per-request log id so
// two responses can be compared for identical shape and message.
func errorBodyWithoutLogID(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	delete(body, "log_id")
	return body
}

func TestRefreshTokenRejectsTokenFromOtherApp(t *testing.T) {
	user := domainuser.Users{Id: "user-1", Name: "Jane Doe", Email: "jane@example.com", Role: "user"}
	foreign, err := otherAppTokens().GenerateRefresh(user.Id, user.Name, user.Role, "log-1")
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}
	badSignature, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": user.Id}).SignedString([]byte("a-different-secret-of-at-least-32-bytes"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sessionSvc := &sessionServiceUserHandlerTestDouble{}
	handler := newUserHandlerForTest()
	handler.SessionSvc = sessionSvc
	userSvc := handler.Service.(*userServiceTestDouble)

	ctx, foreignRec := newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+foreign+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, foreignRec, http.StatusUnauthorized)
	if sessionSvc.rotatedAccess != "" || sessionSvc.rotatedRefresh != "" {
		t.Fatal("expected no new tokens for a refresh token from another app")
	}
	if userSvc.logoutToken != "" {
		t.Fatal("expected the foreign token not to be blacklisted")
	}
	if strings.Contains(foreignRec.Body.String(), "access_token") {
		t.Fatalf("response must not carry tokens: %s", foreignRec.Body.String())
	}

	ctx, badRec := newUserHandlerTestContext(t, http.MethodPost, "/refresh-token", `{"refresh_token":"`+badSignature+`"}`, nil)
	handler.RefreshToken(ctx)
	assertUserHandlerStatus(t, badRec, http.StatusUnauthorized)
	got, want := errorBodyWithoutLogID(t, foreignRec), errorBodyWithoutLogID(t, badRec)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("foreign-app response %v differs from bad-signature response %v", got, want)
	}
}
