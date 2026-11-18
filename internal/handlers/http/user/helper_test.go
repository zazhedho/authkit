package user

import (
	"context"
	"errors"
	"github.com/zazhedho/authkit/internal/config"
	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type appConfigServiceUserTestDouble struct {
	enabled bool
	err     error
	keys    []string
}

func (m *appConfigServiceUserTestDouble) GetAll(ctx context.Context, req dtoappconfig.ListRequest) ([]domainappconfig.AppConfig, int64, error) {
	return nil, 0, nil
}
func (m *appConfigServiceUserTestDouble) GetByID(ctx context.Context, id string) (domainappconfig.AppConfig, error) {
	return domainappconfig.AppConfig{}, nil
}
func (m *appConfigServiceUserTestDouble) GetByKey(ctx context.Context, configKey string) (domainappconfig.AppConfig, error) {
	return domainappconfig.AppConfig{}, nil
}
func (m *appConfigServiceUserTestDouble) Update(ctx context.Context, id string, req dtoappconfig.UpdateAppConfig) (domainappconfig.AppConfig, error) {
	return domainappconfig.AppConfig{}, nil
}
func (m *appConfigServiceUserTestDouble) GetString(ctx context.Context, configKey string, fallback string) (string, error) {
	return fallback, nil
}
func (m *appConfigServiceUserTestDouble) GetBool(ctx context.Context, configKey string, fallback bool) (bool, error) {
	return fallback, nil
}
func (m *appConfigServiceUserTestDouble) GetInt(ctx context.Context, configKey string, fallback int) (int, error) {
	return fallback, nil
}
func (m *appConfigServiceUserTestDouble) GetDuration(ctx context.Context, configKey string, fallback time.Duration) (time.Duration, error) {
	return fallback, nil
}
func (m *appConfigServiceUserTestDouble) DecodeJSON(ctx context.Context, configKey string, target any) error {
	return nil
}
func (m *appConfigServiceUserTestDouble) IsEnabled(ctx context.Context, configKey string, fallback bool) (bool, error) {
	m.keys = append(m.keys, configKey)
	if m.err != nil {
		return false, m.err
	}
	return m.enabled, nil
}

func TestBuildAuthTokenResponse(t *testing.T) {
	handler := New(&userServiceTestDouble{}, nil, nil, nil, Options{
		Settings: Settings{AccessTTL: 12 * time.Hour, RefreshTTL: 72 * time.Hour},
	})

	got := handler.buildAuthTokenResponse("access", "refresh")
	if got["access_token"] != "access" || got["refresh_token"] != "refresh" {
		t.Fatalf("unexpected token response: %+v", got)
	}
	if got["expires_in_hours"] != 12 || got["refresh_expires_in_hours"] != 72 {
		t.Fatalf("unexpected expiry metadata: %+v", got)
	}
}

func TestUserMutationErrorResponseMapping(t *testing.T) {
	logID := uuid.New()
	tests := []struct {
		err  error
		code int
	}{
		{domainuser.ErrNotFound, http.StatusNotFound},
		{domainuser.ErrDuplicate, http.StatusBadRequest},
		{errors.New("email already exists"), http.StatusBadRequest},
		{errors.New("access denied: missing permission"), http.StatusForbidden},
		{errors.New("invalid role: admin"), http.StatusBadRequest},
		{errors.New("database down"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		code, _ := userMutationErrorResponse(logID, tt.err)
		if code != tt.code {
			t.Fatalf("error %v: expected %d, got %d", tt.err, tt.code, code)
		}
	}
}

func TestImpersonationErrorResponseMapping(t *testing.T) {
	logID := uuid.New()
	tests := []struct {
		err  error
		code int
	}{
		{domainuser.ErrNotFound, http.StatusNotFound},
		{errors.New("cannot impersonate superadmin users"), http.StatusForbidden},
		{errors.New("target user id is required"), http.StatusBadRequest},
		{errors.New("database down"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		code, _ := impersonationErrorResponse(logID, tt.err)
		if code != tt.code {
			t.Fatalf("error %v: expected %d, got %d", tt.err, tt.code, code)
		}
	}
}

func TestImpersonationFromClaims(t *testing.T) {
	if got := impersonationFromClaims(nil); got != nil {
		t.Fatalf("expected nil impersonation, got %+v", got)
	}

	got := impersonationFromClaims(map[string]any{
		"is_impersonated":   true,
		"original_user_id":  "admin-1",
		"original_username": "Admin",
		"original_role":     "admin",
	})
	if got == nil || got.userID != "admin-1" || got.username != "Admin" || got.role != "admin" {
		t.Fatalf("unexpected impersonation: %+v", got)
	}
}

func TestRuntimeConfigAndThrottleResponses(t *testing.T) {
	handler := &Handler{}
	enabled, err := handler.isRuntimeConfigEnabled(context.Background(), "missing", true)
	if err != nil || !enabled {
		t.Fatalf("expected fallback config value, enabled=%v err=%v", enabled, err)
	}

	handler.AppConfigService = &appConfigServiceUserTestDouble{enabled: false}
	enabled, err = handler.isRuntimeConfigEnabled(context.Background(), "auth.enabled", true)
	if err != nil || enabled {
		t.Fatalf("expected service config value false, enabled=%v err=%v", enabled, err)
	}

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	handler.respondTooManyLoginAttempts(ctx, uuid.New(), 5*time.Second)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "5" {
		t.Fatalf("unexpected too many attempts response: code=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}

	rec = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(rec)
	handler.respondThrottle(ctx, uuid.New(), 3*time.Second, "")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "3" {
		t.Fatalf("unexpected throttle response: code=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
}

func TestNewUserHandlerAppliesDefaultFlagKeysAndTTLs(t *testing.T) {
	handler := New(&userServiceTestDouble{}, nil, nil, nil, Options{})
	// The handler repeats the root defaults; this keeps the copies in step.
	want := FlagKeys(config.DefaultFlagKeys())
	if handler.Settings.Flags != want {
		t.Fatalf("expected default flag keys %+v, got %+v", want, handler.Settings.Flags)
	}
	if handler.Settings.AccessTTL != token.DefaultAccessTTL || handler.Settings.RefreshTTL != token.DefaultRefreshTTL {
		t.Fatalf("expected default TTLs, got %v %v", handler.Settings.AccessTTL, handler.Settings.RefreshTTL)
	}
	if handler.Settings.OTPCooldown != 60*time.Second || handler.Settings.ResetCooldown != 60*time.Second {
		t.Fatalf("expected default 60s cooldowns, got %v %v", handler.Settings.OTPCooldown, handler.Settings.ResetCooldown)
	}
}

func TestNewUserHandlerKeepsExplicitCooldowns(t *testing.T) {
	handler := New(&userServiceTestDouble{}, nil, nil, nil, Options{
		Settings: Settings{OTPCooldown: 45 * time.Second, ResetCooldown: 2 * time.Minute},
	})
	if handler.Settings.OTPCooldown != 45*time.Second || handler.Settings.ResetCooldown != 2*time.Minute {
		t.Fatalf("explicit cooldowns were overwritten: %v %v", handler.Settings.OTPCooldown, handler.Settings.ResetCooldown)
	}
}

func TestUserHandlerUsesInjectedFlagKeysAndEmailAppName(t *testing.T) {
	appConfig := &appConfigServiceUserTestDouble{enabled: true}
	otp := &otpServiceUserHandlerTestDouble{}
	handler := newUserHandlerForTest()
	handler.AppConfigService = appConfig
	handler.OTPService = otp
	handler.Settings.EmailAppName = "Injected Mail App"
	handler.Settings.Flags = FlagKeys{PublicRegistration: "custom.registration", RegisterOTP: "custom.otp", PasswordResetEmail: "custom.reset"}

	ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/register/otp/send", `{"email":"new@example.com"}`, nil)
	handler.SendRegisterOTP(ctx)
	assertUserHandlerStatus(t, rec, http.StatusOK)

	if len(appConfig.keys) != 2 || appConfig.keys[0] != "custom.registration" || appConfig.keys[1] != "custom.otp" {
		t.Fatalf("expected injected flag keys to be consulted, got %v", appConfig.keys)
	}
	if otp.sentAppName != "Injected Mail App" {
		t.Fatalf("expected injected email app name, got %q", otp.sentAppName)
	}
}

func TestForgotPasswordDevelopmentFallbackDependsOnInjectedAppEnv(t *testing.T) {
	cases := map[string]int{
		"development": http.StatusOK,
		" Local ":     http.StatusOK,
		"test":        http.StatusOK,
		"production":  http.StatusServiceUnavailable,
		"":            http.StatusServiceUnavailable,
	}
	for appEnv, want := range cases {
		handler := newUserHandlerForTest()
		handler.Settings.AppEnv = appEnv
		ctx, rec := newUserHandlerTestContext(t, http.MethodPost, "/forgot-password", `{"email":"jane@example.com"}`, nil)
		handler.ForgotPassword(ctx)
		if rec.Code != want {
			t.Fatalf("AppEnv %q: expected status %d, got %d body=%s", appEnv, want, rec.Code, rec.Body.String())
		}
	}
}
