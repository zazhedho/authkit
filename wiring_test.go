package authkit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/zazhedho/authkit/authutil"
	permissioncache "github.com/zazhedho/authkit/cache/permission"
	domainuser "github.com/zazhedho/authkit/domain/user"
	serviceuser "github.com/zazhedho/authkit/services/user"
	"github.com/zazhedho/authkit/settings"
)

type sentOTP struct {
	to, code, appName string
	ttl               time.Duration
}
type sentReset struct {
	to, token, appName, url string
	ttl                     time.Duration
}

// recordingMailer captures what the kit hands to the Mailer.
type recordingMailer struct {
	mu     sync.Mutex
	otps   []sentOTP
	resets []sentReset
}

func (m *recordingMailer) SendOTP(to, code, appName string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.otps = append(m.otps, sentOTP{to, code, appName, ttl})
	return nil
}

func (m *recordingMailer) SendPasswordReset(to, token, appName, resetURL string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resets = append(m.resets, sentReset{to, token, appName, resetURL, ttl})
	return nil
}

func (m *recordingMailer) lastOTP(t *testing.T) sentOTP {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.otps) == 0 {
		t.Fatal("no OTP was sent")
	}
	return m.otps[len(m.otps)-1]
}

func (m *recordingMailer) lastReset(t *testing.T) sentReset {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.resets) == 0 {
		t.Fatal("no reset email was sent")
	}
	return m.resets[len(m.resets)-1]
}

func doJSON(engine http.Handler, method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	var parsed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	return rec, parsed
}

func dataField(t *testing.T, body map[string]any, key string) any {
	t.Helper()
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("response has no data object: %v", body)
	}
	return data[key]
}

func keyWithPrefix(t *testing.T, mr *miniredis.Miniredis, prefix string) string {
	t.Helper()
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, prefix) {
			return k
		}
	}
	t.Fatalf("no redis key with prefix %q; keys: %v", prefix, mr.Keys())
	return ""
}

// resetRegisterLimit clears the per-IP register limiter counter so tests that
// call the limited routes repeatedly exercise the service behind it.
func resetRegisterLimit(mr *miniredis.Miniredis) {
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, "rate_limit:") {
			mr.Del(k)
		}
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// wiringConfig sets a distinctive, non-default value for every Config field.
func wiringConfig(mailer Mailer) func(*Config) {
	return func(c *Config) {
		c.Mailer = mailer
		c.AppName = "wiring-app"
		c.AppEnv = "wiring-env"
		c.AccessTokenTTL = 7 * time.Hour
		c.RefreshTokenTTL = 50 * time.Hour
		c.DefaultRole = "guest-x"
		c.GoogleClientIDs = []string{"client-1.example.test", "client-2.example.test"}
		c.EmailAppName = "Wiring Mail"
		c.PermissionCacheTTL = 777 * time.Second
		c.Login = settings.LoginLimit{Limit: 2, Window: 33 * time.Second, BlockDuration: 444 * time.Second}
		c.Register = settings.RateLimit{Limit: 2, Window: 55 * time.Second}
		c.OTP = settings.OTPConfig{TTL: 111 * time.Second, Cooldown: 22 * time.Second, RateLimit: 2, RateWindow: 999 * time.Second, MaxAttempts: 2, Secret: "otp-secret-fake"} //nolint:gosec // fake test secret
		c.Reset = settings.PasswordResetConfig{TTL: 333 * time.Second, Cooldown: 44 * time.Second, RateLimit: 3, RateWindow: 888 * time.Second, Secret: "reset-secret-fake", URLTemplate: "https://app.example.test/reset?token={token}"}
		c.Flags = settings.FlagKeys{PublicRegistration: "wiring.registration", RegisterOTP: "wiring.otp", PasswordResetEmail: "wiring.reset"}
	}
}

func TestNewWiresConfigIntoComponents(t *testing.T) {
	mr, client := newMiniRedis(t)
	mailer := &recordingMailer{}
	kit, drv := newTestKit(t, func(c *Config) {
		wiringConfig(mailer)(c)
		c.Redis = client
	})
	engine := mountedEngine(t, kit)

	// Only the custom OTP and reset flag keys are enabled; the default keys are
	// not, so a response that reflects them proves the custom keys were used.
	drv.setConfig("wiring.otp", "true")
	drv.setConfig("wiring.reset", "true")
	drv.addUser(fakeUser{ID: "u-login", Email: "login@example.test", Role: "viewer", PasswordHash: mustHash(t, "Passw0rd!x")})

	t.Run("Tokens carry TTLs and AppName", func(t *testing.T) {
		if got := kit.Tokens().AccessTTL(); got != 7*time.Hour {
			t.Errorf("AccessTTL = %v", got)
		}
		if got := kit.Tokens().RefreshTTL(); got != 50*time.Hour {
			t.Errorf("RefreshTTL = %v", got)
		}
		u := &domainuser.Users{Id: "ttl-user", Role: "viewer"}
		for name, tc := range map[string]struct {
			issue func() (string, error)
			want  time.Duration
		}{
			"access":         {func() (string, error) { return kit.Tokens().Generate(u, "log") }, 7 * time.Hour},
			"refresh":        {func() (string, error) { return kit.Tokens().GenerateRefresh(u, "log", nil) }, 50 * time.Hour},
			"password reset": {func() (string, error) { return kit.Tokens().GeneratePasswordReset(u, "log") }, 333 * time.Second},
		} {
			tok, err := tc.issue()
			if err != nil {
				t.Fatalf("%s token: %v", name, err)
			}
			exp, err := kit.Tokens().ExpiresAt(tok)
			if err != nil {
				t.Fatalf("%s token expiry: %v", name, err)
			}
			if d := time.Until(exp); d < tc.want-time.Minute || d > tc.want+time.Minute {
				t.Errorf("%s token expires in %v, want about %v", name, d, tc.want)
			}
		}
		foreign, err := authutil.NewTokens(authutil.TokenConfig{Key: testJWTKey, AppName: "other-app"})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := foreign.Generate(&domainuser.Users{Id: "x", Role: "viewer"}, "log")
		if err != nil {
			t.Fatal(err)
		}
		if code := do(engine, http.MethodGet, "/api/permissions/me", tok).Code; code != http.StatusUnauthorized {
			t.Errorf("token from another AppName: got %d, want 401", code)
		}
	})

	t.Run("login response, session TTL", func(t *testing.T) {
		rec, body := doJSON(engine, http.MethodPost, "/api/user/login", "", `{"email":"login@example.test","password":"Passw0rd!x"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
		}
		if got := dataField(t, body, "expires_in_hours"); got != float64(7) {
			t.Errorf("expires_in_hours = %v, want 7", got)
		}
		if got := dataField(t, body, "refresh_expires_in_hours"); got != float64(50) {
			t.Errorf("refresh_expires_in_hours = %v, want 50", got)
		}
		sessionKey := keyWithPrefix(t, mr, "session")
		if ttl := mr.TTL(sessionKey); ttl < 49*time.Hour || ttl > 50*time.Hour {
			t.Errorf("session key %q TTL = %v, want about 50h (RefreshTokenTTL)", sessionKey, ttl)
		}
	})

	t.Run("login limiter", func(t *testing.T) {
		const bad = `{"email":"nobody@example.test","password":"Passw0rd!x"}`
		rec, _ := doJSON(engine, http.MethodPost, "/api/user/login", "", bad)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Fatalf("first bad login: %d %s", rec.Code, rec.Body.String())
		}
		attempts := keyWithPrefix(t, mr, "login_attempts:")
		if ttl := mr.TTL(attempts); ttl != 33*time.Second {
			t.Errorf("attempt window = %v, want 33s (Login.Window)", ttl)
		}
		if rec, _ = doJSON(engine, http.MethodPost, "/api/user/login", "", bad); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("second bad login (Login.Limit=2): %d, want 429", rec.Code)
		}
		block := keyWithPrefix(t, mr, "login_block:")
		if ttl := mr.TTL(block); ttl != 444*time.Second {
			t.Errorf("block duration = %v, want 444s (Login.BlockDuration)", ttl)
		}
	})

	t.Run("register limiter", func(t *testing.T) {
		for i := 1; i <= 2; i++ {
			if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register", "", `{}`); rec.Code == http.StatusTooManyRequests {
				t.Fatalf("request %d rate limited too early", i)
			}
		}
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register", "", `{}`); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("third request (Register.Limit=2): %d, want 429", rec.Code)
		}
		key := keyWithPrefix(t, mr, "rate_limit:user_register:")
		if ttl := mr.TTL(key); ttl <= 0 || ttl > 55*time.Second {
			t.Errorf("register window TTL = %v, want within (0, 55s]", ttl)
		}
		// The OTP route shares the same limiter and counter.
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", `{}`); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("otp send behind register limiter: %d, want 429", rec.Code)
		}
	})

	t.Run("register status reflects OTP cooldown and flag key", func(t *testing.T) {
		rec, body := doJSON(engine, http.MethodGet, "/api/user/register/status", "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d", rec.Code)
		}
		if got := dataField(t, body, "otp_cooldown"); got != float64(22) {
			t.Errorf("otp_cooldown = %v, want 22", got)
		}
		if got := dataField(t, body, "otp_enabled"); got != true {
			t.Errorf("otp_enabled = %v, want true (Flags.RegisterOTP key)", got)
		}
	})

	t.Run("permission cache TTL", func(t *testing.T) {
		drv.addUser(fakeUser{ID: "u-audit", Role: "viewer", Permissions: []string{"audits:list"}})
		if code := do(engine, http.MethodGet, "/api/audits", tokenFor(t, kit, "u-audit", "viewer")).Code; code == http.StatusForbidden || code == http.StatusUnauthorized {
			t.Fatalf("audits: %d", code)
		}
		if ttl := mr.TTL(permissioncache.Key("u-audit")); ttl != 777*time.Second {
			t.Errorf("permission cache TTL = %v, want 777s", ttl)
		}
	})

	t.Run("OTP service", func(t *testing.T) {
		// The register limiter above exhausted this IP's budget; reset it.
		mr.FlushAll()
		const send = `{"email":"otp1@example.test"}`
		resetRegisterLimit(mr)
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", send); rec.Code != http.StatusOK {
			t.Fatalf("send: %d %s", rec.Code, rec.Body.String())
		}
		sent := mailer.lastOTP(t)
		if sent.appName != "Wiring Mail" || sent.to != "otp1@example.test" {
			t.Errorf("sent = %+v, want appName Wiring Mail (EmailAppName)", sent)
		}
		if sent.ttl != 111*time.Second {
			t.Errorf("mailer got ttl %v, want the configured OTP.TTL 111s", sent.ttl)
		}
		stored, err := mr.Get("otp:register:otp1@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if want := sha256Hex(sent.code + "otp-secret-fake"); stored != want {
			t.Errorf("stored OTP hash does not use OTP.Secret")
		}
		for key, want := range map[string]time.Duration{
			"otp:register:otp1@example.test": 111 * time.Second,
			"otp:cooldown:otp1@example.test": 22 * time.Second,
			"otp:rate:otp1@example.test":     999 * time.Second,
		} {
			if got := mr.TTL(key); got != want {
				t.Errorf("TTL(%s) = %v, want %v", key, got, want)
			}
		}

		resetRegisterLimit(mr)
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", send); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("send during cooldown: %d, want 429", rec.Code)
		}
		mr.FastForward(23 * time.Second)
		resetRegisterLimit(mr)
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", send); rec.Code != http.StatusOK {
			t.Fatalf("second send (RateLimit=2): %d", rec.Code)
		}
		mr.FastForward(23 * time.Second)
		resetRegisterLimit(mr)
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", send); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("third send (OTP.RateLimit=2): %d, want 429", rec.Code)
		}
	})

	t.Run("OTP max attempts", func(t *testing.T) {
		mr.FlushAll()
		const email = "otp2@example.test"
		resetRegisterLimit(mr)
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", `{"email":"`+email+`"}`); rec.Code != http.StatusOK {
			t.Fatalf("send: %d", rec.Code)
		}
		good := mailer.lastOTP(t).code
		wrong := "000000"
		if good == wrong {
			wrong = "111111"
		}
		body := func(code string) string {
			return `{"name":"Some Person","email":"` + email + `","phone":"081234567890","password":"Passw0rd!x","otp_code":"` + code + `"}`
		}
		for i := 1; i <= 2; i++ {
			resetRegisterLimit(mr)
			if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register", "", body(wrong)); rec.Code != http.StatusBadRequest {
				t.Fatalf("wrong code #%d: %d", i, rec.Code)
			}
		}
		// OTP.MaxAttempts=2 burned the OTP, so even the right code is refused now.
		resetRegisterLimit(mr)
		rec, parsed := doJSON(engine, http.MethodPost, "/api/user/register", "", body(good))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("correct code after max attempts: %d, want 400 (%v)", rec.Code, parsed)
		}
	})

	t.Run("password reset service", func(t *testing.T) {
		mr.FlushAll()
		const forgot = `{"email":"login@example.test"}`
		rec, body := doJSON(engine, http.MethodPost, "/api/user/forgot-password", "", forgot)
		if rec.Code != http.StatusOK {
			t.Fatalf("forgot: %d %s", rec.Code, rec.Body.String())
		}
		if got := dataField(t, body, "cooldown"); got != float64(44) {
			t.Errorf("cooldown = %v, want 44 (Reset.Cooldown)", got)
		}
		sent := mailer.lastReset(t)
		if sent.appName != "Wiring Mail" {
			t.Errorf("appName = %q, want EmailAppName", sent.appName)
		}
		if sent.ttl != 333*time.Second {
			t.Errorf("ttl = %v, want 333s (Reset.TTL)", sent.ttl)
		}
		if want := "https://app.example.test/reset?token=" + sent.token; sent.url != want {
			t.Errorf("url = %q, want %q (Reset.URLTemplate)", sent.url, want)
		}
		tokenKey := "reset:token:" + sha256Hex(sent.token+"reset-secret-fake")
		if got := mr.TTL(tokenKey); got != 333*time.Second {
			t.Errorf("TTL(token key, Reset.Secret) = %v, want 333s", got)
		}
		for key, want := range map[string]time.Duration{
			"reset:cooldown:login@example.test": 44 * time.Second,
			"reset:rate:login@example.test":     888 * time.Second,
		} {
			if got := mr.TTL(key); got != want {
				t.Errorf("TTL(%s) = %v, want %v", key, got, want)
			}
		}
		for i := 2; i <= 3; i++ {
			mr.FastForward(45 * time.Second)
			if rec, _ := doJSON(engine, http.MethodPost, "/api/user/forgot-password", "", forgot); rec.Code != http.StatusOK {
				t.Fatalf("request %d: %d", i, rec.Code)
			}
		}
		mr.FastForward(45 * time.Second)
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/forgot-password", "", forgot); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("fourth request (Reset.RateLimit=3): %d, want 429", rec.Code)
		}
	})
}

func TestNewWiresServiceSettings(t *testing.T) {
	kit, _ := newTestKit(t, wiringConfig(nil))
	svc, ok := kit.Users().(*serviceuser.ServiceUser)
	if !ok {
		t.Fatalf("Users() is %T", kit.Users())
	}
	if svc.DefaultRole != "guest-x" {
		t.Errorf("DefaultRole = %q", svc.DefaultRole)
	}
	if len(svc.GoogleClientIDs) != 2 || svc.GoogleClientIDs[0] != "client-1.example.test" {
		t.Errorf("GoogleClientIDs = %v", svc.GoogleClientIDs)
	}
}

func TestNewWiresDefaultRoleIntoRegistration(t *testing.T) {
	kit, _ := newTestKit(t, func(c *Config) { c.DefaultRole = "Guest-X" })
	engine := mountedEngine(t, kit)
	rec, body := doJSON(engine, http.MethodPost, "/api/user/register", "",
		`{"name":"Some Person","email":"reg@example.test","phone":"081234567890","password":"Passw0rd!x"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	if got := dataField(t, body, "role"); got != "guest-x" {
		t.Errorf("registered role = %v, want guest-x", got)
	}
}

func TestNewWiresRegistrationFlagKey(t *testing.T) {
	kit, drv := newTestKit(t, func(c *Config) { c.Flags.PublicRegistration = "wiring.registration" })
	drv.setConfig("wiring.registration", "false")
	rec, body := doJSON(mountedEngine(t, kit), http.MethodGet, "/api/user/register/status", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if got := dataField(t, body, "enabled"); got != false {
		t.Errorf("enabled = %v, want false (Flags.PublicRegistration key)", got)
	}
}

func TestNewWiresAppEnvIntoPasswordResetFallback(t *testing.T) {
	// With e-mail reset disabled, forgot-password falls back to a development
	// flow that is allowed only in development-like environments.
	for env, wantUnavailable := range map[string]bool{"production": true, "local": false} {
		kit, _ := newTestKit(t, func(c *Config) { c.AppEnv = env })
		rec, _ := doJSON(mountedEngine(t, kit), http.MethodPost, "/api/user/forgot-password", "", `{"email":"x@example.test"}`)
		if got := rec.Code == http.StatusServiceUnavailable; got != wantUnavailable {
			t.Errorf("AppEnv=%s: status %d, unavailable=%v want %v", env, rec.Code, got, wantUnavailable)
		}
	}
}

func TestNewWithoutRedisHasNoLimitersAndInertOTPAndReset(t *testing.T) {
	kit, drv := newTestKit(t, func(c *Config) { c.Login.Limit = 2; c.Mailer = &recordingMailer{} })
	engine := mountedEngine(t, kit)
	drv.setConfig("auth.register_otp_enabled", "true")

	for i := 0; i < 5; i++ {
		rec, _ := doJSON(engine, http.MethodPost, "/api/user/login", "", `{"email":"nobody@example.test","password":"Passw0rd!x"}`)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("login limited without Redis on attempt %d", i+1)
		}
		rec, _ = doJSON(engine, http.MethodPost, "/api/user/register", "", `{}`)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("register limited without Redis on attempt %d", i+1)
		}
	}
	rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", `{"email":"a@example.test"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("OTP send without Redis: %d, want 503", rec.Code)
	}
}

func TestNewWithRedisButNoMailerKeepsOTPAndResetInert(t *testing.T) {
	mr, client := newMiniRedis(t)
	kit, drv := newTestKit(t, func(c *Config) { c.Redis = client; c.Login.Limit = 2 })
	engine := mountedEngine(t, kit)
	drv.setConfig("auth.register_otp_enabled", "true")
	drv.setConfig("auth.password_reset_email_enabled", "true")
	drv.addUser(fakeUser{ID: "u1", Email: "u1@example.test", Role: "viewer"})

	rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", `{"email":"a@example.test"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("OTP send without Mailer: %d, want 503", rec.Code)
	}
	rec, _ = doJSON(engine, http.MethodPost, "/api/user/forgot-password", "", `{"email":"u1@example.test"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("forgot-password without Mailer: %d, want 503", rec.Code)
	}
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, "otp:") || strings.HasPrefix(k, "reset:") {
			t.Errorf("unexpected redis key %q written by an inert service", k)
		}
	}
	// The login limiter is still active with Redis.
	const bad = `{"email":"nobody@example.test","password":"Passw0rd!x"}`
	doJSON(engine, http.MethodPost, "/api/user/login", "", bad)
	if rec, _ = doJSON(engine, http.MethodPost, "/api/user/login", "", bad); rec.Code != http.StatusTooManyRequests {
		t.Errorf("second bad login with Redis: %d, want 429", rec.Code)
	}
}
