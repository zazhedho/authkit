package authkit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/zazhedho/authkit/internal/config"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	cachepermission "github.com/zazhedho/authkit/internal/infrastructure/cache/permission"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	serviceuser "github.com/zazhedho/authkit/internal/services/user"
	"github.com/zazhedho/authkit/internal/testutil"
)

const testJWTKey = "test-secret-must-be-at-least-32-bytes"

func init() { gin.SetMode(gin.TestMode) }

func testConfig(db *gorm.DB) Config {
	return Config{DB: db, AppName: "testapp", JWTKey: testJWTKey}
}

func newTestKit(t *testing.T, mutate func(*Config)) (*Kit, *testutil.Driver) {
	t.Helper()
	db, drv := testutil.NewDB(t)
	cfg := testConfig(db)
	if mutate != nil {
		mutate(&cfg)
	}
	kit, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return kit, drv
}

func registeredRoutes(engine *gin.Engine) []string {
	got := make([]string, 0, len(engine.Routes()))
	for _, r := range engine.Routes() {
		got = append(got, r.Method+" "+r.Path)
	}
	sort.Strings(got)
	return got
}

func newMiniRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func mountedEngine(t *testing.T, kit *Kit) *gin.Engine {
	t.Helper()
	engine := gin.New()
	kit.Mount(engine.Group("/api"))
	return engine
}

func tokenFor(t *testing.T, kit *Kit, id, role string) string {
	t.Helper()
	tok, err := kit.IssueAccessToken(id, "User "+id, role)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	return tok
}

func do(engine http.Handler, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	db, _ := testutil.NewDB(t)

	if _, err := New(Config{AppName: "testapp", JWTKey: testJWTKey}); err == nil {
		t.Fatal("expected error for nil DB")
	}
	short := testConfig(db)
	short.JWTKey = "too-short"
	if _, err := New(short); err == nil {
		t.Fatal("expected error for short JWT key")
	}
	noName := testConfig(db)
	noName.AppName = ""
	if _, err := New(noName); err == nil {
		t.Fatal("expected error for empty AppName")
	}
}

func TestNewWithoutRedisOrMailer(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	if kit.Audit() == nil || kit.AppConfig() == nil {
		t.Fatal("accessors must be non-nil")
	}
	if kit.Auth() == nil || kit.Can("a", "b") == nil || kit.Role("x") == nil || kit.LoadPermissions() == nil {
		t.Fatal("middleware constructors must be non-nil")
	}
}

func TestNewDoesNotTouchDatabase(t *testing.T) {
	kit, drv := newTestKit(t, nil)
	_ = kit
	if queries := drv.Queries(); len(queries) != 0 {
		t.Fatalf("New must not query the database, got %v", queries)
	}
}

func TestCanAllowsAndDenies(t *testing.T) {
	kit, drv := newTestKit(t, nil)
	drv.AddUser(testutil.User{ID: "u-allowed", Role: "viewer", Permissions: []string{"trips:create"}})
	drv.AddUser(testutil.User{ID: "u-denied", Role: "viewer", Permissions: []string{"trips:view"}})
	drv.AddUser(testutil.User{ID: "u-super", Role: "superadmin"})

	engine := gin.New()
	group := engine.Group("/x")
	group.Use(kit.Auth(), kit.Can("trips", "create"))
	group.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"with permission", tokenFor(t, kit, "u-allowed", "viewer"), http.StatusOK},
		{"without permission", tokenFor(t, kit, "u-denied", "viewer"), http.StatusForbidden},
		{"superadmin", tokenFor(t, kit, "u-super", "superadmin"), http.StatusOK},
		{"no token", "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(engine, http.MethodGet, "/x/ping", tc.token).Code; got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRoleAllowsAndDenies(t *testing.T) {
	kit, drv := newTestKit(t, nil)
	drv.AddUser(testutil.User{ID: "a", Role: "admin"})
	drv.AddUser(testutil.User{ID: "v", Role: "viewer"})
	engine := gin.New()
	group := engine.Group("/x")
	group.Use(kit.Auth(), kit.Role("admin"))
	group.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	if got := do(engine, http.MethodGet, "/x/ping", tokenFor(t, kit, "a", "admin")).Code; got != http.StatusOK {
		t.Fatalf("admin: got %d", got)
	}
	if got := do(engine, http.MethodGet, "/x/ping", tokenFor(t, kit, "v", "viewer")).Code; got != http.StatusForbidden {
		t.Fatalf("viewer: got %d", got)
	}
}

func TestScopeFromReturnsAuthenticatedUser(t *testing.T) {
	kit, drv := newTestKit(t, nil)
	drv.AddUser(testutil.User{ID: "user-42", Role: "viewer"})
	var gotID, gotRole string
	engine := gin.New()
	engine.GET("/who", kit.Auth(), func(c *gin.Context) {
		s := ScopeFrom(c.Request.Context())
		gotID, gotRole = s.UserID, s.Role
		c.Status(http.StatusOK)
	})

	if code := do(engine, http.MethodGet, "/who", tokenFor(t, kit, "user-42", "viewer")).Code; code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	if gotID != "user-42" || gotRole != "viewer" {
		t.Fatalf("scope = %q/%q", gotID, gotRole)
	}
}

func TestIssueAccessTokenPassesAuth(t *testing.T) {
	kit, drv := newTestKit(t, nil)
	drv.AddUser(testutil.User{ID: "user-7", Role: RoleStaff})
	engine := gin.New()
	engine.GET("/who", kit.Auth(), func(c *gin.Context) {
		s := ScopeFrom(c.Request.Context())
		c.JSON(http.StatusOK, gin.H{"id": s.UserID, "name": s.Username, "role": s.Role})
	})

	tok, err := kit.IssueAccessToken("user-7", "Seven", RoleStaff)
	if err != nil || tok == "" {
		t.Fatalf("IssueAccessToken: %q, %v", tok, err)
	}
	rec := do(engine, http.MethodGet, "/who", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("issued token rejected by Auth: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != "user-7" || got["name"] != "Seven" || got["role"] != RoleStaff {
		t.Fatalf("scope = %v", got)
	}
	if code := do(engine, http.MethodGet, "/who", "").Code; code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", code)
	}
}

func TestScopeHelpers(t *testing.T) {
	ctx := WithScope(context.Background(), NewScope("u1", "One", RoleViewer, []string{"trips:view"}))
	s := ScopeFrom(ctx)
	if s.UserID != "u1" || s.Role != RoleViewer || !s.Has("trips", "view") || s.Has("trips", "delete") {
		t.Fatalf("scope round trip failed: %+v", s)
	}
}

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

// lastOTP waits briefly: the code is sent after the route has answered.
func (m *recordingMailer) lastOTP(t *testing.T) sentOTP {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		m.mu.Lock()
		n := len(m.otps)
		m.mu.Unlock()
		if n > 0 {
			break
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.otps) == 0 {
		t.Fatal("no OTP was sent")
	}
	return m.otps[len(m.otps)-1]
}

// lastReset waits briefly: forgot-password sends after it has answered.
func (m *recordingMailer) lastReset(t *testing.T) sentReset {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		m.mu.Lock()
		n := len(m.resets)
		m.mu.Unlock()
		if n > 0 {
			break
		}
	}
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

func otpHMAC(purpose, email, code, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(purpose + email + code))
	return hex.EncodeToString(mac.Sum(nil))
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
		c.Login = config.LoginLimit{Limit: 2, Window: 33 * time.Second, BlockDuration: 444 * time.Second}
		c.Register = config.RateLimit{Limit: 2, Window: 55 * time.Second}
		c.OTP = config.OTPConfig{TTL: 111 * time.Second, Cooldown: 22 * time.Second, RateLimit: 2, RateWindow: 999 * time.Second, MaxAttempts: 2, Secret: "otp-secret-fake-0123456789-abcdef-0123456789"} //nolint:gosec // fake test secret
		c.Reset = config.PasswordResetConfig{TTL: 333 * time.Second, Cooldown: 44 * time.Second, RateLimit: 3, RateWindow: 888 * time.Second, Secret: "reset-secret-fake-0123456789-abcdef-0123456789", URLTemplate: "https://app.example.test/reset?token={token}"}
		c.Flags = config.FlagKeys{PublicRegistration: "wiring.registration", RegisterOTP: "wiring.otp", PasswordResetEmail: "wiring.reset"}
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
	drv.SetConfig("wiring.otp", "true")
	drv.SetConfig("wiring.reset", "true")
	drv.AddUser(testutil.User{ID: "u-login", Email: "login@example.test", Role: "viewer", PasswordHash: testutil.MustHash(t, "Passw0rd!x")})

	t.Run("Tokens carry TTLs and AppName", func(t *testing.T) {
		if got := kit.tokens.AccessTTL(); got != 7*time.Hour {
			t.Errorf("AccessTTL = %v", got)
		}
		if got := kit.tokens.RefreshTTL(); got != 50*time.Hour {
			t.Errorf("RefreshTTL = %v", got)
		}
		u := &domainuser.Users{ID: "ttl-user", Role: "viewer"}
		for name, tc := range map[string]struct {
			issue func() (string, error)
			want  time.Duration
		}{
			"access":  {func() (string, error) { return kit.tokens.Generate(u.ID, u.Name, u.Role, "log") }, 7 * time.Hour},
			"refresh": {func() (string, error) { return kit.tokens.GenerateRefresh(u.ID, u.Name, u.Role, "log") }, 50 * time.Hour},
		} {
			tok, err := tc.issue()
			if err != nil {
				t.Fatalf("%s token: %v", name, err)
			}
			exp, err := kit.tokens.ExpiresAt(tok)
			if err != nil {
				t.Fatalf("%s token expiry: %v", name, err)
			}
			if d := time.Until(exp); d < tc.want-time.Minute || d > tc.want+time.Minute {
				t.Errorf("%s token expires in %v, want about %v", name, d, tc.want)
			}
		}
		foreign, err := token.New(token.Config{Key: testJWTKey, AppName: "other-app", AccessTTL: time.Hour, RefreshTTL: 2 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := foreign.Generate("x", "", "viewer", "log")
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
		drv.AddUser(testutil.User{ID: "u-audit", Role: "viewer", Permissions: []string{"audits:list"}})
		if code := do(engine, http.MethodGet, "/api/audits", tokenFor(t, kit, "u-audit", "viewer")).Code; code == http.StatusForbidden || code == http.StatusUnauthorized {
			t.Fatalf("audits: %d", code)
		}
		if ttl := mr.TTL(cachepermission.Key("u-audit")); ttl != 777*time.Second {
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
		if want := otpHMAC("register", "otp1@example.test", sent.code, "otp-secret-fake-0123456789-abcdef-0123456789"); stored != want {
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

		// Throttled sends still answer 200 (the route never reveals throttling)
		// but send nothing; only the mail count shows the limits at work.
		sendOTP := func(wantMails int) {
			t.Helper()
			resetRegisterLimit(mr)
			if rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", send); rec.Code != http.StatusOK {
				t.Fatalf("send: %d, want 200", rec.Code)
			}
			time.Sleep(300 * time.Millisecond)
			if n := mailer.otpCount(); n != wantMails {
				t.Fatalf("mails sent = %d, want %d", n, wantMails)
			}
		}
		sendOTP(1) // cooldown
		mr.FastForward(23 * time.Second)
		sendOTP(2) // second send (RateLimit=2)
		mr.FastForward(23 * time.Second)
		sendOTP(2) // third send is rate limited
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
		tokenKey := "reset:token:" + sha256Hex(sent.token+"reset-secret-fake-0123456789-abcdef-0123456789")
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
			waitForResets(t, mailer, i)
		}
		// The throttled fourth request still answers 200 (the route never
		// reveals throttling) but sends nothing.
		mr.FastForward(45 * time.Second)
		if rec, _ := doJSON(engine, http.MethodPost, "/api/user/forgot-password", "", forgot); rec.Code != http.StatusOK {
			t.Fatalf("fourth request: %d, want 200", rec.Code)
		}
		time.Sleep(300 * time.Millisecond)
		if n := mailer.resetCount(); n != 3 {
			t.Fatalf("resets sent = %d, want 3 (Reset.RateLimit=3)", n)
		}
	})
}

func (m *recordingMailer) otpCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.otps)
}

func (m *recordingMailer) resetCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.resets)
}

func waitForResets(t *testing.T, m *recordingMailer, want int) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if m.resetCount() >= want {
			return
		}
	}
	t.Fatalf("resets sent = %d, want %d", m.resetCount(), want)
}

func TestNewWiresServiceSettings(t *testing.T) {
	kit, _ := newTestKit(t, wiringConfig(nil))
	svc, ok := kit.users.(*serviceuser.Service)
	if !ok {
		t.Fatalf("Users() is %T", kit.users)
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
	drv.SetConfig("wiring.registration", "false")
	rec, body := doJSON(mountedEngine(t, kit), http.MethodGet, "/api/user/register/status", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if got := dataField(t, body, "enabled"); got != false {
		t.Errorf("enabled = %v, want false (Flags.PublicRegistration key)", got)
	}
}

func TestForgotPasswordNeverReturnsATokenInAnyEnv(t *testing.T) {
	// The legacy development fallback that put a reset token in the response
	// is gone: every AppEnv answers the same 200 without a token.
	for _, env := range []string{"production", "local", "development", "test"} {
		kit, _ := newTestKit(t, func(c *Config) { c.AppEnv = env })
		rec, _ := doJSON(mountedEngine(t, kit), http.MethodPost, "/api/user/forgot-password", "", `{"email":"x@example.test"}`)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "token") {
			t.Errorf("AppEnv=%s: status %d body %s", env, rec.Code, rec.Body.String())
		}
	}
}

func TestNewWithoutRedisHasNoLimitersAndInertOTPAndReset(t *testing.T) {
	kit, drv := newTestKit(t, func(c *Config) { c.Login.Limit = 2; c.Mailer = &recordingMailer{} })
	engine := mountedEngine(t, kit)
	drv.SetConfig("auth.register_otp_enabled", "true")

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
	drv.SetConfig("auth.register_otp_enabled", "true")
	drv.SetConfig("auth.password_reset_email_enabled", "true")
	drv.AddUser(testutil.User{ID: "u1", Email: "u1@example.test", Role: "viewer"})

	rec, _ := doJSON(engine, http.MethodPost, "/api/user/register/otp/send", "", `{"email":"a@example.test"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("OTP send without Mailer: %d, want 503", rec.Code)
	}
	rec, _ = doJSON(engine, http.MethodPost, "/api/user/forgot-password", "", `{"email":"u1@example.test"}`)
	if rec.Code != http.StatusOK {
		t.Errorf("forgot-password without Mailer: %d, want 200 (always the same answer)", rec.Code)
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

func TestAuthRejectsATokenForAUserThatDoesNotExist(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	engine := gin.New()
	engine.GET("/who", kit.Auth(), func(c *gin.Context) { c.Status(http.StatusOK) })
	if code := do(engine, http.MethodGet, "/who", tokenFor(t, kit, "ghost", "superadmin")).Code; code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401: a signed token must not outlive its user", code)
	}
}

func TestAuthRequiresARedisSessionForLoginTokens(t *testing.T) {
	_, client := newMiniRedis(t)
	kit, drv := newTestKit(t, func(c *Config) { c.Redis = client })
	drv.AddUser(testutil.User{ID: "u1", Role: "viewer"})
	engine := gin.New()
	engine.GET("/who", kit.Auth(), func(c *gin.Context) { c.Status(http.StatusOK) })

	// A login-style token without a session index entry is revoked.
	loginToken, err := kit.tokens.Generate("u1", "User", "viewer", "log")
	if err != nil {
		t.Fatal(err)
	}
	if code := do(engine, http.MethodGet, "/who", loginToken).Code; code != http.StatusUnauthorized {
		t.Fatalf("token without a session: got %d, want 401", code)
	}
	// The tooling token carries no session and passes.
	if code := do(engine, http.MethodGet, "/who", tokenFor(t, kit, "u1", "viewer")).Code; code != http.StatusOK {
		t.Fatalf("tooling token: got %d, want 200", code)
	}
}

func TestAuthRoutesShareAPerIPLimit(t *testing.T) {
	for _, route := range []string{"/api/user/google/login", "/api/user/refresh-token", "/api/user/forgot-password", "/api/user/reset-password"} {
		_, c := newMiniRedis(t)
		k, _ := newTestKit(t, func(cfg *Config) { cfg.Redis = c; cfg.AuthRate = RateLimit{Limit: 1, Window: time.Minute} })
		e := mountedEngine(t, k)
		doJSON(e, http.MethodPost, route, "", `{}`)
		if rec, _ := doJSON(e, http.MethodPost, route, "", `{}`); rec.Code != http.StatusTooManyRequests {
			t.Errorf("%s: second request got %d, want 429", route, rec.Code)
		}
	}
}

func TestNewTreatsATypedNilRedisAsDisabled(t *testing.T) {
	var typedNil *redis.Client
	kit, _ := newTestKit(t, func(c *Config) { c.Redis = typedNil })
	for _, r := range registeredRoutes(mountedEngine(t, kit)) {
		if strings.Contains(r, "/sessions") || strings.Contains(r, "/session/") {
			t.Fatalf("session route %s mounted for a typed-nil Redis", r)
		}
	}
}

func TestMountServesPublicAndProtectedRoutes(t *testing.T) {
	kit, _ := newTestKit(t, nil)
	engine := mountedEngine(t, kit)
	if code := do(engine, http.MethodGet, "/api/user/register/status", "").Code; code != http.StatusOK {
		t.Fatalf("public route: got %d, want 200", code)
	}
	if code := do(engine, http.MethodGet, "/api/users", "").Code; code != http.StatusUnauthorized {
		t.Fatalf("protected route: got %d, want 401", code)
	}
	if got := len(registeredRoutes(engine)); got != 42 {
		t.Fatalf("%d routes without Redis, want 42", got)
	}
	_, client := newMiniRedis(t)
	withRedis, _ := newTestKit(t, func(c *Config) { c.Redis = client })
	if got := len(registeredRoutes(mountedEngine(t, withRedis))); got != 45 {
		t.Fatalf("%d routes with Redis, want 45", got)
	}
}
