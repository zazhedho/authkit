package authkit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/gokit"
	"gorm.io/gorm"

	"github.com/zazhedho/authkit/internal/config"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
)

const testJWTKey = "test-secret-must-be-at-least-32-bytes"

type mailerTestDouble struct{}

func (mailerTestDouble) SendOTP(string, string, string, time.Duration) error { return nil }
func (mailerTestDouble) SendPasswordReset(string, string, string, string, time.Duration) error {
	return nil
}

// validConfig returns a defaulted config that passes Validate, with Redis and
// Mailer set so the OTP and reset secrets are required.
func validConfig() Config {
	cfg := Config{
		DB:      &gorm.DB{},
		Redis:   redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"}),
		Mailer:  mailerTestDouble{},
		AppName: "test-app",
		JWTKey:  testJWTKey,
	}
	cfg.OTP.Secret = "fake-otp-secret-0123456789-abcdef-0123456789"
	cfg.Reset.Secret = "fake-reset-secret-0123456789-abcdef-0123456789"
	return cfg.withDefaults()
}

// legacyEnvNames lists every variable ConfigFromEnv reads.
var legacyEnvNames = []string{
	"APP_NAME",
	"APP_ENV",
	"JWT_KEY",
	"JWT_EXP",
	"REFRESH_TOKEN_EXP_HOURS",
	"GOOGLE_CLIENT_ID",
	"GOOGLE_CLIENT_IDS",
	"AUTH_EMAIL_APP_NAME",
	"PERMISSION_CACHE_TTL",
	"PERMISSION_CACHE_TTL_SECONDS",
	"LOGIN_ATTEMPT_LIMIT",
	"LOGIN_ATTEMPT_WINDOW_SECONDS",
	"LOGIN_BLOCK_DURATION_SECONDS",
	"REGISTER_RATE_LIMIT",
	"REGISTER_RATE_WINDOW_SECONDS",
	"OTP_SECRET",
	"OTP_TTL",
	"OTP_TTL_SECONDS",
	"OTP_COOLDOWN",
	"OTP_COOLDOWN_SECONDS",
	"OTP_RATE_LIMIT",
	"OTP_RATE_WINDOW",
	"OTP_RATE_WINDOW_SECONDS",
	"OTP_MAX_ATTEMPTS",
	"RESET_SECRET",
	"RESET_TTL",
	"RESET_TTL_SECONDS",
	"RESET_COOLDOWN",
	"RESET_COOLDOWN_SECONDS",
	"RESET_RATE_LIMIT",
	"RESET_RATE_WINDOW",
	"RESET_RATE_WINDOW_SECONDS",
	"RESET_URL_TEMPLATE",
	"RESET_URL",
	"CONFIG_PUBLIC_REGISTRATION",
	"CONFIG_REGISTER_OTP",
	"CONFIG_PASSWORD_RESET_EMAIL",
}

// clearLegacyEnv blanks every variable ConfigFromEnv reads so a test does not
// depend on the developer's shell. An empty value behaves like an unset one.
func clearLegacyEnv(t *testing.T) {
	t.Helper()
	for _, name := range legacyEnvNames {
		t.Setenv(name, "")
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantIs  error
		wantMsg string
	}{
		{"nil DB", func(c *Config) { c.DB = nil }, nil, "DB"},
		{"empty AppName", func(c *Config) { c.AppName = "" }, nil, "AppName"},
		{"blank AppName", func(c *Config) { c.AppName = "   " }, nil, "AppName"},
		{"empty JWTKey", func(c *Config) { c.JWTKey = "" }, token.ErrJWTKeyNotConfigured, "JWTKey"},
		{"31 character JWTKey", func(c *Config) { c.JWTKey = strings.Repeat("k", 31) }, token.ErrJWTKeyTooShort, "JWTKey"},
		{"superadmin DefaultRole", func(c *Config) { c.DefaultRole = "superadmin" }, nil, "DefaultRole"},
		{"admin DefaultRole", func(c *Config) { c.DefaultRole = "admin" }, nil, "DefaultRole"},
		{"normalized privileged DefaultRole", func(c *Config) { c.DefaultRole = "  SuperAdmin " }, nil, "DefaultRole"},
		{"missing OTP secret", func(c *Config) { c.OTP.Secret = "" }, nil, "OTP.Secret"},
		{"blank OTP secret", func(c *Config) { c.OTP.Secret = "  " }, nil, "OTP.Secret"},
		{"missing Reset secret", func(c *Config) { c.Reset.Secret = "" }, nil, "Reset.Secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("expected %v, got %v", tc.wantIs, err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("expected error to mention %q, got %q", tc.wantMsg, err.Error())
			}
		})
	}
}

func TestValidateAllowsMissingOTPAndResetSecretsWithoutRedisOrMailer(t *testing.T) {
	cases := map[string]func(*Config){
		"no redis":  func(c *Config) { c.Redis = nil },
		"no mailer": func(c *Config) { c.Mailer = nil },
		"neither":   func(c *Config) { c.Redis, c.Mailer = nil, nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			mutate(&cfg)
			cfg.OTP.Secret, cfg.Reset.Secret = "", ""
			if err := cfg.Validate(); err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
		})
	}
}

func TestWithDefaultsMatchesLegacyEnvDefaults(t *testing.T) {
	cfg := Config{AppName: "test-app"}.withDefaults()

	if cfg.AccessTokenTTL != 15*time.Minute || cfg.RefreshTokenTTL != 168*time.Hour {
		t.Fatalf("unexpected token TTLs: %v %v", cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	}
	if cfg.DefaultRole != "viewer" {
		t.Fatalf("unexpected default role %q", cfg.DefaultRole)
	}
	if cfg.PermissionCacheTTL != 300*time.Second {
		t.Fatalf("unexpected permission cache TTL %v", cfg.PermissionCacheTTL)
	}
	if cfg.Login != (config.LoginLimit{Limit: 5, Window: 60 * time.Second, BlockDuration: 300 * time.Second}) {
		t.Fatalf("unexpected login limit %+v", cfg.Login)
	}
	if cfg.Register != (config.RateLimit{Limit: 5, Window: 60 * time.Second}) {
		t.Fatalf("unexpected register limit %+v", cfg.Register)
	}
	wantOTP := config.OTPConfig{TTL: 300 * time.Second, Cooldown: 60 * time.Second, RateLimit: 5, RateWindow: 300 * time.Second, MaxAttempts: 5, Secret: ""}
	if cfg.OTP != wantOTP {
		t.Fatalf("unexpected OTP config %+v", cfg.OTP)
	}
	wantReset := config.PasswordResetConfig{TTL: 900 * time.Second, Cooldown: 60 * time.Second, RateLimit: 5, RateWindow: 900 * time.Second, Secret: ""}
	if cfg.Reset != wantReset {
		t.Fatalf("unexpected reset config %+v", cfg.Reset)
	}
	wantFlags := config.FlagKeys{
		PublicRegistration: "auth.public_registration_enabled",
		RegisterOTP:        "auth.register_otp_enabled",
		PasswordResetEmail: "auth.password_reset_email_enabled",
	}
	if cfg.Flags != wantFlags {
		t.Fatalf("unexpected flags %+v", cfg.Flags)
	}
	if cfg.EmailAppName != cfg.AppName {
		t.Fatalf("expected EmailAppName to default to AppName, got %q", cfg.EmailAppName)
	}
}

func TestWithDefaultsKeepsExplicitValues(t *testing.T) {
	in := Config{
		AppName:            "test-app",
		EmailAppName:       "Mail App",
		DefaultRole:        "member",
		AccessTokenTTL:     time.Hour,
		RefreshTokenTTL:    2 * time.Hour,
		PermissionCacheTTL: time.Minute,
		OTP:                config.OTPConfig{TTL: 10 * time.Minute},
	}
	got := in.withDefaults()
	if got.EmailAppName != "Mail App" || got.DefaultRole != "member" || got.AccessTokenTTL != time.Hour ||
		got.RefreshTokenTTL != 2*time.Hour || got.PermissionCacheTTL != time.Minute {
		t.Fatalf("explicit values were overwritten: %+v", got)
	}
	if got.OTP.TTL != 10*time.Minute || got.OTP.RateWindow != 10*time.Minute {
		t.Fatalf("expected OTP rate window to follow explicit TTL, got %+v", got.OTP)
	}
}

func TestConfigFromEnvReadsLegacyNames(t *testing.T) {
	clearLegacyEnv(t)
	env := map[string]string{ //nolint:gosec // fake values for a test
		"APP_NAME":                     "test-app",
		"APP_ENV":                      "development",
		"JWT_KEY":                      testJWTKey,
		"JWT_EXP":                      "2",
		"REFRESH_TOKEN_EXP_HOURS":      "48",
		"GOOGLE_CLIENT_ID":             "a",
		"GOOGLE_CLIENT_IDS":            "b, c",
		"AUTH_EMAIL_APP_NAME":          "Mail App",
		"PERMISSION_CACHE_TTL_SECONDS": "120",
		"LOGIN_ATTEMPT_LIMIT":          "7",
		"LOGIN_ATTEMPT_WINDOW_SECONDS": "70",
		"LOGIN_BLOCK_DURATION_SECONDS": "700",
		"REGISTER_RATE_LIMIT":          "9",
		"REGISTER_RATE_WINDOW_SECONDS": "90",
		"OTP_SECRET":                   "fake-otp-secret-0123456789-abcdef-0123456789",
		"OTP_TTL_SECONDS":              "200",
		"OTP_COOLDOWN_SECONDS":         "30",
		"OTP_RATE_LIMIT":               "4",
		"OTP_RATE_WINDOW_SECONDS":      "400",
		"OTP_MAX_ATTEMPTS":             "3",
		"RESET_SECRET":                 "fake-reset-secret-0123456789-abcdef-0123456789",
		"RESET_TTL_SECONDS":            "600",
		"RESET_COOLDOWN_SECONDS":       "45",
		"RESET_RATE_LIMIT":             "6",
		"RESET_RATE_WINDOW_SECONDS":    "1200",
		"RESET_URL_TEMPLATE":           "https://example.com/reset?token={token}",
		"CONFIG_PUBLIC_REGISTRATION":   "custom.registration",
		"CONFIG_REGISTER_OTP":          "custom.otp",
		"CONFIG_PASSWORD_RESET_EMAIL":  "custom.reset_email",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}

	cfg := ConfigFromEnv()

	if cfg.DB != nil || cfg.Redis != nil || cfg.Mailer != nil {
		t.Fatal("ConfigFromEnv must not fill DB, Redis or Mailer")
	}
	if cfg.AppName != "test-app" || cfg.AppEnv != "development" || cfg.JWTKey != testJWTKey || cfg.EmailAppName != "Mail App" {
		t.Fatalf("unexpected identity fields: %+v", cfg)
	}
	if cfg.AccessTokenTTL != 2*time.Hour || cfg.RefreshTokenTTL != 48*time.Hour || cfg.PermissionCacheTTL != 120*time.Second {
		t.Fatalf("unexpected TTLs: %v %v %v", cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.PermissionCacheTTL)
	}
	got := slices.Clone(cfg.GoogleClientIDs)
	slices.Sort(got)
	if !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("unexpected google client ids %v", cfg.GoogleClientIDs)
	}
	if cfg.Login != (config.LoginLimit{Limit: 7, Window: 70 * time.Second, BlockDuration: 700 * time.Second}) {
		t.Fatalf("unexpected login limit %+v", cfg.Login)
	}
	if cfg.Register != (config.RateLimit{Limit: 9, Window: 90 * time.Second}) {
		t.Fatalf("unexpected register limit %+v", cfg.Register)
	}
	wantOTP := config.OTPConfig{TTL: 200 * time.Second, Cooldown: 30 * time.Second, RateLimit: 4, RateWindow: 400 * time.Second, MaxAttempts: 3, Secret: "fake-otp-secret-0123456789-abcdef-0123456789"} //nolint:gosec // fake test secret
	if cfg.OTP != wantOTP {
		t.Fatalf("unexpected OTP config %+v", cfg.OTP)
	}
	wantReset := config.PasswordResetConfig{TTL: 600 * time.Second, Cooldown: 45 * time.Second, RateLimit: 6, RateWindow: 1200 * time.Second, Secret: "fake-reset-secret-0123456789-abcdef-0123456789", URLTemplate: "https://example.com/reset?token={token}"} //nolint:gosec // fake test secret
	if cfg.Reset != wantReset {
		t.Fatalf("unexpected reset config %+v", cfg.Reset)
	}
	if cfg.Flags != (config.FlagKeys{PublicRegistration: "custom.registration", RegisterOTP: "custom.otp", PasswordResetEmail: "custom.reset_email"}) {
		t.Fatalf("unexpected flags %+v", cfg.Flags)
	}
}

func TestConfigFromEnvPrefersDurationStrings(t *testing.T) {
	clearLegacyEnv(t)
	t.Setenv("OTP_TTL_SECONDS", "300")
	t.Setenv("OTP_TTL", "7m")
	t.Setenv("OTP_COOLDOWN_SECONDS", "60")
	t.Setenv("OTP_COOLDOWN", "90s")
	t.Setenv("OTP_RATE_WINDOW_SECONDS", "100")
	t.Setenv("OTP_RATE_WINDOW", "10m")
	t.Setenv("OTP_MAX_ATTEMPTS", "3")
	t.Setenv("OTP_RATE_LIMIT", "9")
	t.Setenv("OTP_SECRET", " fake-otp-secret-0123456789-abcdef-0123456789 ")
	t.Setenv("RESET_TTL_SECONDS", "900")
	t.Setenv("RESET_TTL", "20m")
	t.Setenv("RESET_COOLDOWN_SECONDS", "30")
	t.Setenv("RESET_COOLDOWN", "2m")
	t.Setenv("RESET_RATE_WINDOW_SECONDS", "30")
	t.Setenv("RESET_RATE_WINDOW", "30m")
	t.Setenv("RESET_RATE_LIMIT", "7")
	t.Setenv("RESET_SECRET", " fake-reset-secret-0123456789-abcdef-0123456789 ")
	t.Setenv("PERMISSION_CACHE_TTL_SECONDS", "120")
	t.Setenv("PERMISSION_CACHE_TTL", "10m")

	cfg := ConfigFromEnv()

	if cfg.OTP.TTL != 7*time.Minute || cfg.OTP.Cooldown != 90*time.Second || cfg.OTP.RateWindow != 10*time.Minute {
		t.Fatalf("unexpected OTP durations: %+v", cfg.OTP)
	}
	if cfg.OTP.MaxAttempts != 3 || cfg.OTP.RateLimit != 9 || cfg.OTP.Secret != "fake-otp-secret-0123456789-abcdef-0123456789" {
		t.Fatalf("unexpected OTP scalars: %+v", cfg.OTP)
	}
	if cfg.Reset.TTL != 20*time.Minute || cfg.Reset.Cooldown != 2*time.Minute || cfg.Reset.RateWindow != 30*time.Minute {
		t.Fatalf("unexpected reset durations: %+v", cfg.Reset)
	}
	if cfg.Reset.RateLimit != 7 || cfg.Reset.Secret != "fake-reset-secret-0123456789-abcdef-0123456789" {
		t.Fatalf("unexpected reset scalars: %+v", cfg.Reset)
	}
	if cfg.PermissionCacheTTL != 10*time.Minute {
		t.Fatalf("expected duration form of permission cache TTL, got %v", cfg.PermissionCacheTTL)
	}
}

func TestConfigFromEnvRateWindowsDefaultToTTL(t *testing.T) {
	clearLegacyEnv(t)
	t.Setenv("OTP_TTL", "7m")
	t.Setenv("RESET_TTL_SECONDS", "1000")

	cfg := ConfigFromEnv()

	if cfg.OTP.RateWindow != 7*time.Minute {
		t.Fatalf("expected OTP rate window to follow TTL, got %v", cfg.OTP.RateWindow)
	}
	if cfg.Reset.RateWindow != 1000*time.Second {
		t.Fatalf("expected reset rate window to follow TTL, got %v", cfg.Reset.RateWindow)
	}
}

func TestConfigFromEnvResetURLFallback(t *testing.T) {
	clearLegacyEnv(t)
	t.Setenv("RESET_URL_TEMPLATE", "")
	t.Setenv("RESET_URL", "https://example.com/reset?token={token}")
	if got := ConfigFromEnv().Reset.URLTemplate; got != "https://example.com/reset?token={token}" {
		t.Fatalf("expected RESET_URL fallback, got %q", got)
	}

	t.Setenv("RESET_URL_TEMPLATE", "https://example.com/primary")
	if got := ConfigFromEnv().Reset.URLTemplate; got != "https://example.com/primary" {
		t.Fatalf("expected RESET_URL_TEMPLATE to win, got %q", got)
	}
}

func TestConfigFromEnvNonPositiveRegisterWindowDefaultsTo60s(t *testing.T) {
	clearLegacyEnv(t)
	for _, v := range []string{"0", "-5"} {
		t.Setenv("REGISTER_RATE_WINDOW_SECONDS", v)
		if got := ConfigFromEnv().Register.Window; got != 60*time.Second {
			t.Fatalf("REGISTER_RATE_WINDOW_SECONDS=%s: expected 60s, got %v", v, got)
		}
	}
}

func TestConfigFromEnvEmailAppNameFallsBackToAppName(t *testing.T) {
	clearLegacyEnv(t)
	t.Setenv("APP_NAME", "test-app")
	t.Setenv("AUTH_EMAIL_APP_NAME", "")
	if got := ConfigFromEnv().EmailAppName; got != "test-app" {
		t.Fatalf("expected APP_NAME fallback, got %q", got)
	}
}

func TestConfigFromEnvHasNoBuiltInSecrets(t *testing.T) {
	clearLegacyEnv(t)
	t.Setenv("OTP_SECRET", "")
	t.Setenv("RESET_SECRET", "")
	t.Setenv("JWT_KEY", "")

	cfg := ConfigFromEnv()
	if cfg.OTP.Secret != "" || cfg.Reset.Secret != "" || cfg.JWTKey != "" {
		t.Fatalf("expected no built-in secrets, got otp=%q reset=%q jwt=%q", cfg.OTP.Secret, cfg.Reset.Secret, cfg.JWTKey)
	}
}

func TestConfigFromEnvPermissionCacheTTL(t *testing.T) {
	clearLegacyEnv(t)
	cases := []struct {
		name, duration, seconds string
		want                    time.Duration
	}{
		{"duration form wins over seconds", "2m", "5", 2 * time.Minute},
		{"falls back to seconds form", "bad", "30", 30 * time.Second},
		{"falls back to five minutes", "bad", "0", 5 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PERMISSION_CACHE_TTL", tc.duration)
			t.Setenv("PERMISSION_CACHE_TTL_SECONDS", tc.seconds)
			if got := ConfigFromEnv().PermissionCacheTTL; got != tc.want {
				t.Fatalf("PermissionCacheTTL = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestConfigPrintingRedactsSecrets(t *testing.T) {
	cfg := validConfig()
	cfg.JWTKey = "jwt-secret-value-0123456789abcdefghij"
	cfg.OTP.Secret = "otp-secret-value-xyz-0123456789-abcdef-0123"
	cfg.Reset.Secret = "reset-secret-value-xyz-0123456789-abcdef-0123"
	out := fmt.Sprintf("%v %+v %#v %s", cfg, cfg, cfg, &cfg)
	for _, secret := range []string{cfg.JWTKey, cfg.OTP.Secret, cfg.Reset.Secret} {
		if strings.Contains(out, secret) {
			t.Fatalf("printed config leaks %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, "JWTKey:set") {
		t.Fatalf("printed config should report that JWTKey is set: %s", out)
	}
	if empty := fmt.Sprint(Config{}); !strings.Contains(empty, "JWTKey:unset") {
		t.Fatalf("empty config should report unset: %s", empty)
	}
}

// goSources returns the non-test Go files under the repo root (slash paths).
func goSources(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	repoFS := os.DirFS(".")
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".superpowers":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := fs.ReadFile(repoFS, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(path)] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Go sources found; test must run from the repo root")
	}
	return files
}

func TestNoEnvReadsOutsideAllowedFiles(t *testing.T) {
	forbidden := []string{"GetEnv(", "DurationFromEnv(", "os.Getenv(", "os.LookupEnv("}
	allowed := func(path string) bool {
		return path == "config.go" || strings.HasPrefix(path, "cmd/")
	}
	for path, src := range goSources(t) {
		if allowed(path) {
			continue
		}
		for _, needle := range forbidden {
			if strings.Contains(src, needle) {
				t.Errorf("%s reads the environment via %q; only config.go and cmd/ may", path, needle)
			}
		}
	}
}

func TestNoBuiltInSecretLiterals(t *testing.T) {
	for path, src := range goSources(t) {
		for _, needle := range []string{"otp-secret", "reset-secret"} {
			if strings.Contains(src, needle) {
				t.Errorf("%s contains the built-in secret literal %q", path, needle)
			}
		}
	}
}

func TestValidateRejectsShortOTPAndResetSecrets(t *testing.T) {
	cfg := validConfig()
	cfg.OTP.Secret = strings.Repeat("a", 31)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "OTP.Secret") {
		t.Fatalf("31-character OTP.Secret: err = %v", err)
	}
	cfg = validConfig()
	cfg.Reset.Secret = strings.Repeat("a", 31)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "Reset.Secret") {
		t.Fatalf("31-character Reset.Secret: err = %v", err)
	}
	cfg = validConfig()
	cfg.OTP.Secret, cfg.Reset.Secret = strings.Repeat("a", 32), strings.Repeat("b", 32)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("32-character secrets: %v", err)
	}
	// Without Redis and Mailer the secrets are unused, but one that is set must
	// still be long enough.
	cfg = validConfig()
	cfg.Redis, cfg.Mailer, cfg.OTP.Secret = nil, nil, "short"
	if err := cfg.Validate(); err == nil {
		t.Fatal("a short OTP.Secret must be rejected even when unused")
	}
}

func TestAuthRateDefaults(t *testing.T) {
	cfg := validConfig()
	if cfg.AuthRate.Limit != 30 || cfg.AuthRate.Window != time.Minute {
		t.Fatalf("AuthRate = %+v, want 30 per minute", cfg.AuthRate)
	}
}

func TestConfigFromEnvStrictReportsUnparsableVariables(t *testing.T) {
	clearLegacyEnv(t)
	t.Cleanup(gokit.ResetEnvErrors)
	gokit.ResetEnvErrors()
	t.Setenv("APP_NAME", "app")
	if _, err := ConfigFromEnvStrict(); err != nil {
		t.Fatalf("clean environment: %v", err)
	}
	t.Setenv("OTP_RATE_LIMIT", "five")
	cfg, err := ConfigFromEnvStrict()
	if err == nil || !strings.Contains(err.Error(), "OTP_RATE_LIMIT") {
		t.Fatalf("err = %v, want it to name OTP_RATE_LIMIT", err)
	}
	if cfg.AppName != "app" {
		t.Fatalf("the config built so far must still be returned: %+v", cfg)
	}
}

func TestMailerCanBeSplitIntoOTPAndReset(t *testing.T) {
	cfg := validConfig()
	cfg.Mailer = nil
	cfg.OTPMailer = mailerTestDouble{}
	cfg.Reset.Secret = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("only an OTPMailer: the reset secret must not be required: %v", err)
	}
	cfg.OTP.Secret = ""
	cfg.Reset.Secret = strings.Repeat("r", 32)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "OTP.Secret") {
		t.Fatalf("an OTPMailer needs OTP.Secret: %v", err)
	}
	cfg = validConfig()
	cfg.Mailer = nil
	cfg.ResetMailer = mailerTestDouble{}
	cfg.OTP.Secret = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("only a ResetMailer: %v", err)
	}
	if cfg.otpMailer() != nil || cfg.resetMailer() == nil {
		t.Fatal("the flows must use their own mailer only")
	}
	both := validConfig()
	if both.otpMailer() == nil || both.resetMailer() == nil {
		t.Fatal("Mailer feeds both flows")
	}
}
