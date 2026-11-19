// Package authkit provides users, sessions, RBAC, audit and app config for gin
// services: build a Config, New, Kit.Migrate, Kit.Mount. Only ConfigFromEnv
// reads the environment.
package authkit

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	httpappconfig "github.com/zazhedho/authkit/internal/handlers/http/appconfig"
	httpaudit "github.com/zazhedho/authkit/internal/handlers/http/audit"
	httpmenu "github.com/zazhedho/authkit/internal/handlers/http/menu"
	"github.com/zazhedho/authkit/internal/handlers/http/middleware"
	httppermission "github.com/zazhedho/authkit/internal/handlers/http/permission"
	httprole "github.com/zazhedho/authkit/internal/handlers/http/role"
	httpsession "github.com/zazhedho/authkit/internal/handlers/http/session"
	httpuser "github.com/zazhedho/authkit/internal/handlers/http/user"
	cachepermission "github.com/zazhedho/authkit/internal/infrastructure/cache/permission"
	"github.com/zazhedho/authkit/internal/infrastructure/ratelimit"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	repositoryappconfig "github.com/zazhedho/authkit/internal/repositories/appconfig"
	repositoryaudit "github.com/zazhedho/authkit/internal/repositories/audit"
	repositoryauth "github.com/zazhedho/authkit/internal/repositories/auth"
	repositorymenu "github.com/zazhedho/authkit/internal/repositories/menu"
	repositoryotp "github.com/zazhedho/authkit/internal/repositories/otp"
	repositorypermission "github.com/zazhedho/authkit/internal/repositories/permission"
	repositoryreset "github.com/zazhedho/authkit/internal/repositories/reset"
	repositoryrole "github.com/zazhedho/authkit/internal/repositories/role"
	repositorysession "github.com/zazhedho/authkit/internal/repositories/session"
	repositoryuser "github.com/zazhedho/authkit/internal/repositories/user"
	serviceappconfig "github.com/zazhedho/authkit/internal/services/appconfig"
	serviceaudit "github.com/zazhedho/authkit/internal/services/audit"
	servicemenu "github.com/zazhedho/authkit/internal/services/menu"
	serviceotp "github.com/zazhedho/authkit/internal/services/otp"
	servicepermission "github.com/zazhedho/authkit/internal/services/permission"
	servicereset "github.com/zazhedho/authkit/internal/services/reset"
	servicerole "github.com/zazhedho/authkit/internal/services/role"
	servicesession "github.com/zazhedho/authkit/internal/services/session"
	serviceuser "github.com/zazhedho/authkit/internal/services/user"
)

// Kit is the assembled users, auth and RBAC module. Build it once with New and
// mount its routes with Mount; it is safe for concurrent use after New returns.
type Kit struct {
	cfg Config

	tokens     *token.Tokens
	middleware *middleware.Middleware

	users     httpuser.Service // kept for white-box wiring tests
	audit     AuditService
	appConfig AppConfigService

	userHandler       *httpuser.Handler
	roleHandler       *httprole.Handler
	permissionHandler *httppermission.Handler
	menuHandler       *httpmenu.Handler
	appConfigHandler  *httpappconfig.Handler
	auditHandler      *httpaudit.Handler
	sessionHandler    *httpsession.Handler // nil without Redis

	registerLimiter gin.HandlerFunc
}

// startupWarnings returns the warnings New logs for risky configuration.
func startupWarnings(redisNil bool) []string {
	var out []string
	if redisNil {
		out = append(out, "authkit: Redis is not configured: login rate limiting, register rate limiting, "+
			"sessions, OTP and email password reset are inactive")
	}
	return out
}

// New validates cfg (after defaults) and wires everything without touching the
// database. Nil Redis or Mailer is allowed; dependent features become inert (see README).
func New(cfg Config) (*Kit, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	for _, w := range startupWarnings(cfg.Redis == nil) {
		logus.Log(logus.LevelWarn, w)
	}

	tokens, err := token.NewTokens(token.Config{
		Key:        cfg.JWTKey,
		AppName:    cfg.AppName,
		AccessTTL:  cfg.AccessTokenTTL,
		RefreshTTL: cfg.RefreshTokenTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("authkit: tokens: %w", err)
	}

	db := cfg.DB
	blacklistRepo := repositoryauth.NewRepository(db)
	userRepo := repositoryuser.NewRepository(db)
	roleRepo := repositoryrole.NewRepository(db)
	permissionRepo := repositorypermission.NewRepository(db)
	menuRepo := repositorymenu.NewRepository(db)

	invalidator := cachepermission.NewInvalidator(cfg.Redis)

	auditCore := serviceaudit.NewService(repositoryaudit.NewRepository(db))
	appConfigCore := serviceappconfig.NewService(repositoryappconfig.NewRepository(db))
	auditSvc := auditFacade{auditCore}
	appConfigSvc := appConfigFacade{appConfigCore}
	userSvc := serviceuser.NewService(userRepo, blacklistRepo, roleRepo, permissionRepo, serviceuser.Options{
		Tokens:          tokens,
		DefaultRole:     cfg.DefaultRole,
		GoogleClientIDs: cfg.GoogleClientIDs,
		PhoneLogin:      cfg.PhoneLogin,
		PermissionCache: invalidator,
	})

	// Without Redis: no login limiter or sessions, and OTP/reset get nil deps.
	// With Redis but no Mailer only the limiter and sessions are active.
	var (
		loginLimiter ratelimit.LoginLimiter
		sessionSvc   httpuser.SessionService // stays a nil interface without Redis
		sessionHdlr  *httpsession.Handler
		sessionRepo  *repositorysession.Repository
		otpSvc       httpuser.OTPService   // nil interface until Redis and a Mailer exist
		resetSvc     httpuser.ResetService // likewise
	)
	if cfg.Redis != nil {
		loginLimiter = ratelimit.NewRedisLoginLimiter(cfg.Redis, cfg.Login.Limit, cfg.Login.Window, cfg.Login.BlockDuration)
		sessionRepo = repositorysession.NewRepository(cfg.Redis)
		sessions := servicesession.NewService(sessionRepo, cfg.RefreshTokenTTL)
		sessionSvc = sessions
		sessionHdlr = httpsession.New(sessions, auditSvc)
		if cfg.Mailer != nil {
			otpSvc = serviceotp.NewService(repositoryotp.NewRepository(cfg.Redis), cfg.Mailer, serviceotp.Config(cfg.OTP))
			resetSvc = servicereset.NewService(repositoryreset.NewRepository(cfg.Redis), cfg.Mailer, servicereset.Config(cfg.Reset))
		}
	}

	authMiddleware := middleware.NewMiddleware(blacklistRepo, permissionRepo, cachepermission.NewCache(cfg.Redis), tokens, cfg.PermissionCacheTTL)
	authMiddleware.Users = userRepo
	authMiddleware.StateCache = cachepermission.NewCache(cfg.Redis)
	if sessionRepo != nil {
		authMiddleware.Sessions = sessionRepo
	}

	return &Kit{
		cfg:        cfg,
		tokens:     tokens,
		middleware: authMiddleware,
		users:      userSvc,
		audit:      auditSvc,
		appConfig:  appConfigSvc,
		userHandler: httpuser.New(userSvc, sessionSvc, loginLimiter, auditSvc, httpuser.Options{
			AppConfigService: appConfigSvc,
			OTPService:       otpSvc,
			ResetService:     resetSvc,
			Tokens:           tokens,
			Settings: httpuser.Settings{
				AppEnv:             cfg.AppEnv,
				EmailAppName:       cfg.EmailAppName,
				AccessTTL:          cfg.AccessTokenTTL,
				RefreshTTL:         cfg.RefreshTokenTTL,
				SessionMaxLifetime: cfg.SessionMaxLifetime,
				OTPCooldown:        cfg.OTP.Cooldown,
				ResetCooldown:      cfg.Reset.Cooldown,
				Flags:              httpuser.FlagKeys(cfg.Flags),
			},
		}),
		roleHandler:       httprole.New(servicerole.NewService(roleRepo, permissionRepo, menuRepo, invalidator), auditSvc),
		permissionHandler: httppermission.New(servicepermission.NewService(permissionRepo, invalidator), auditSvc),
		menuHandler:       httpmenu.New(servicemenu.NewService(menuRepo, permissionRepo), auditSvc),
		appConfigHandler:  httpappconfig.New(appConfigCore, auditSvc),
		auditHandler:      httpaudit.New(auditCore),
		sessionHandler:    sessionHdlr,
		registerLimiter:   registerRateLimit(cfg),
	}, nil
}

// registerRateLimit limits the registration endpoints per client IP. It lets
// every request through when there is no Redis to count in or when the limit
// is switched off (gokit panics on a non-positive limit or window, and a nil
// *redis.Client must not reach it wrapped in an interface). Redis failures
// fail open.
func registerRateLimit(cfg Config) gin.HandlerFunc {
	if cfg.Redis == nil || cfg.Register.Limit <= 0 || cfg.Register.Window <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	return gokit.IPRateLimit(gokit.RateLimitOptions{
		Redis:  cfg.Redis,
		Prefix: "user_register",
		Limit:  cfg.Register.Limit,
		Window: cfg.Register.Window,
	})
}

// Auth returns the middleware that requires a valid access token and puts the
// authenticated scope on the request context.
func (k *Kit) Auth() gin.HandlerFunc { return k.middleware.AuthMiddleware() }

// Can returns the middleware that requires the authenticated user to hold the
// (resource, action) permission. Superadmin bypasses it. Use it after Auth.
func (k *Kit) Can(resource, action string) gin.HandlerFunc {
	return k.middleware.PermissionMiddleware(resource, action)
}

// LoadPermissions returns the middleware that loads the user's permissions into
// the scope without requiring any, so a handler can branch on Scope.Has (for
// "_any" style checks). Use it after Auth.
func (k *Kit) LoadPermissions() gin.HandlerFunc {
	return k.middleware.LoadPermissionsMiddleware()
}

// Role returns the middleware that requires the authenticated user to have one
// of the allowed roles. Superadmin bypasses it. Use it after Auth.
func (k *Kit) Role(allowed ...string) gin.HandlerFunc {
	return k.middleware.RoleMiddleware(allowed...)
}

// Audit returns the kit's audit trail service, for recording and querying
// events from your own handlers.
func (k *Kit) Audit() AuditService { return k.audit }

// AppConfig returns the kit's app-config service, which backs the feature
// flags the kit consults at request time.
func (k *Kit) AppConfig() AppConfigService { return k.appConfig }

// IssueAccessToken issues an access token for tests and tooling. Auth still
// requires the user to exist, uses the user's current role and honors
// tokens_valid_after, but the token has no session, so Redis session checks
// skip it.
func (k *Kit) IssueAccessToken(userID, name, role string) (string, error) {
	return k.tokens.GenerateWithClaims(userID, name, role, "authkit-issued", &token.AppClaims{NoSession: true})
}

// ScopeFrom returns the scope on ctx. After Auth alone the permission set is
// empty (Has is false for non-superadmins); Can or LoadPermissions loads it.
func ScopeFrom(ctx context.Context) Scope { return domainauth.FromContext(ctx) }
