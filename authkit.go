// Package authkit assembles users, auth sessions, RBAC, an audit trail and app
// configuration for gin services from explicit configuration. Everything is
// imported from this one path: build a Config (ConfigFromEnv is optional), call
// New, run Kit.Migrate, then Kit.Mount the routes and protect your own routes
// with Kit.Auth, Kit.Can and Kit.Role. Request-time code never reads the
// environment: ConfigFromEnv (config.go) is the only place that does.
package authkit

import (
	"context"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit/internal/authscope"
	"github.com/zazhedho/authkit/internal/authutil"
	permissioncache "github.com/zazhedho/authkit/internal/cache/permission"
	"github.com/zazhedho/authkit/internal/devenv"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	handlerappconfig "github.com/zazhedho/authkit/internal/handlers/appconfig"
	handleraudit "github.com/zazhedho/authkit/internal/handlers/audit"
	handlermenu "github.com/zazhedho/authkit/internal/handlers/menu"
	handlerpermission "github.com/zazhedho/authkit/internal/handlers/permission"
	handlerrole "github.com/zazhedho/authkit/internal/handlers/role"
	handlersession "github.com/zazhedho/authkit/internal/handlers/session"
	handleruser "github.com/zazhedho/authkit/internal/handlers/user"
	interfacesession "github.com/zazhedho/authkit/internal/interfaces/session"
	interfaceuser "github.com/zazhedho/authkit/internal/interfaces/user"
	"github.com/zazhedho/authkit/internal/middlewares"
	repoappconfig "github.com/zazhedho/authkit/internal/repositories/appconfig"
	repoaudit "github.com/zazhedho/authkit/internal/repositories/audit"
	repoauth "github.com/zazhedho/authkit/internal/repositories/auth"
	repomenu "github.com/zazhedho/authkit/internal/repositories/menu"
	repootp "github.com/zazhedho/authkit/internal/repositories/otp"
	repopermission "github.com/zazhedho/authkit/internal/repositories/permission"
	reporeset "github.com/zazhedho/authkit/internal/repositories/reset"
	reporole "github.com/zazhedho/authkit/internal/repositories/role"
	reposession "github.com/zazhedho/authkit/internal/repositories/session"
	repouser "github.com/zazhedho/authkit/internal/repositories/user"
	"github.com/zazhedho/authkit/internal/security"
	serviceappconfig "github.com/zazhedho/authkit/internal/services/appconfig"
	serviceaudit "github.com/zazhedho/authkit/internal/services/audit"
	servicemenu "github.com/zazhedho/authkit/internal/services/menu"
	serviceotp "github.com/zazhedho/authkit/internal/services/otp"
	servicepermission "github.com/zazhedho/authkit/internal/services/permission"
	servicereset "github.com/zazhedho/authkit/internal/services/reset"
	servicerole "github.com/zazhedho/authkit/internal/services/role"
	servicesession "github.com/zazhedho/authkit/internal/services/session"
	serviceuser "github.com/zazhedho/authkit/internal/services/user"
	"github.com/zazhedho/authkit/internal/settings"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
)

// Kit is the assembled users, auth and RBAC module. Build it once with New and
// mount its routes with Mount; it is safe for concurrent use after New returns.
type Kit struct {
	cfg Config

	tokens     *authutil.Tokens
	middleware *middlewares.Middleware

	users     interfaceuser.ServiceUserInterface // kept for white-box wiring tests
	audit     AuditService
	appConfig AppConfigService

	userHandler       *handleruser.HandlerUser
	roleHandler       *handlerrole.RoleHandler
	permissionHandler *handlerpermission.PermissionHandler
	menuHandler       *handlermenu.MenuHandler
	appConfigHandler  *handlerappconfig.AppConfigHandler
	auditHandler      *handleraudit.AuditHandler
	sessionHandler    *handlersession.HandlerSession // nil without Redis

	registerLimiter gin.HandlerFunc
}

// startupWarnings returns the warnings New logs for risky configuration. They
// never contain configuration values other than the fixed AppEnv names.
func startupWarnings(appEnv string, redisNil bool) []string {
	var out []string
	if devenv.IsDev(appEnv) {
		out = append(out, "authkit: AppEnv is a development value ("+strings.Join(devenv.Values, ", ")+"): "+
			"when the email password reset flag is disabled, POST /user/forgot-password returns a password reset token "+
			"directly in the API response for any registered email; never enable this mode on a reachable server")
	}
	if redisNil {
		out = append(out, "authkit: Redis is not configured: login rate limiting, register rate limiting, "+
			"sessions, OTP and email password reset are inactive")
	}
	return out
}

// New validates cfg (after applying defaults) and wires every repository,
// service, handler and middleware once. It never queries or migrates the
// database, and a nil Redis or nil Mailer is allowed: without Redis there is no
// login limiter, no session management and no register rate limit; without
// Redis and a Mailer, registration OTP and password reset e-mail are inert.
func New(cfg Config) (*Kit, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	for _, w := range startupWarnings(cfg.AppEnv, cfg.Redis == nil) {
		logus.WriteLog(logus.LogLevelWarn, w)
	}

	tokens, err := authutil.NewTokens(authutil.TokenConfig{
		Key:        cfg.JWTKey,
		AppName:    cfg.AppName,
		AccessTTL:  cfg.AccessTokenTTL,
		RefreshTTL: cfg.RefreshTokenTTL,
		ResetTTL:   cfg.Reset.TTL,
	})
	if err != nil {
		return nil, fmt.Errorf("authkit: tokens: %w", err)
	}

	db := cfg.DB
	blacklistRepo := repoauth.NewBlacklistRepo(db)
	userRepo := repouser.NewUserRepo(db)
	roleRepo := reporole.NewRoleRepo(db)
	permissionRepo := repopermission.NewPermissionRepo(db)
	menuRepo := repomenu.NewMenuRepo(db)

	invalidator := permissioncache.NewInvalidator(cfg.Redis)

	auditSvc := serviceaudit.NewAuditService(repoaudit.NewAuditRepo(db))
	appConfigSvc := serviceappconfig.NewAppConfigService(repoappconfig.NewAppConfigRepo(db))
	userSvc := serviceuser.NewUserService(userRepo, blacklistRepo, roleRepo, permissionRepo, serviceuser.UserServiceOptions{
		Tokens:          tokens,
		DefaultRole:     cfg.DefaultRole,
		GoogleClientIDs: cfg.GoogleClientIDs,
		PermissionCache: invalidator,
	})

	// Without Redis there is no login limiter and no session service, and the
	// OTP and password reset services get a nil repository and sender, exactly
	// like the original router. With Redis but no Mailer only the limiter and
	// sessions are active.
	var (
		loginLimiter security.LoginLimiter
		sessionSvc   interfacesession.ServiceSessionInterface
		sessionHdlr  *handlersession.HandlerSession
		otpSvc       = serviceotp.NewOTPService(nil, nil, cfg.OTP)
		resetSvc     = servicereset.NewPasswordResetService(nil, nil, cfg.Reset)
	)
	if cfg.Redis != nil {
		loginLimiter = security.NewRedisLoginLimiter(cfg.Redis, cfg.Login.Limit, cfg.Login.Window, cfg.Login.BlockDuration)
		sessionSvc = servicesession.NewSessionService(reposession.NewSessionRepository(cfg.Redis), cfg.RefreshTokenTTL)
		sessionHdlr = handlersession.NewSessionHandler(sessionSvc, auditSvc)
		if cfg.Mailer != nil {
			otpSvc = serviceotp.NewOTPService(repootp.NewOTPRepository(cfg.Redis), cfg.Mailer, cfg.OTP)
			resetSvc = servicereset.NewPasswordResetService(reporeset.NewPasswordResetRepository(cfg.Redis), cfg.Mailer, cfg.Reset)
		}
	}

	return &Kit{
		cfg:        cfg,
		tokens:     tokens,
		middleware: middlewares.NewMiddleware(blacklistRepo, permissionRepo, cfg.Redis, tokens, cfg.PermissionCacheTTL),
		users:      userSvc,
		audit:      auditSvc,
		appConfig:  appConfigSvc,
		userHandler: handleruser.NewUserHandler(userSvc, blacklistRepo, sessionSvc, loginLimiter, auditSvc, handleruser.UserHandlerOptions{
			AppConfigService: appConfigSvc,
			OTPService:       otpSvc,
			ResetService:     resetSvc,
			Tokens:           tokens,
			Settings: settings.UserHandler{
				AppEnv:        cfg.AppEnv,
				EmailAppName:  cfg.EmailAppName,
				AccessTTL:     cfg.AccessTokenTTL,
				RefreshTTL:    cfg.RefreshTokenTTL,
				OTPCooldown:   cfg.OTP.Cooldown,
				ResetCooldown: cfg.Reset.Cooldown,
				Flags:         cfg.Flags,
			},
		}),
		roleHandler:       handlerrole.NewRoleHandler(servicerole.NewRoleService(roleRepo, permissionRepo, menuRepo, invalidator), auditSvc),
		permissionHandler: handlerpermission.NewPermissionHandler(servicepermission.NewPermissionService(permissionRepo, invalidator), auditSvc),
		menuHandler:       handlermenu.NewMenuHandler(servicemenu.NewMenuService(menuRepo, permissionRepo), auditSvc),
		appConfigHandler:  handlerappconfig.NewAppConfigHandler(appConfigSvc, auditSvc),
		auditHandler:      handleraudit.NewAuditHandler(auditSvc),
		sessionHandler:    sessionHdlr,
		registerLimiter:   gokit.IPRateLimitMiddleware(cfg.Redis, "user_register", cfg.Register.Limit, cfg.Register.Window),
	}, nil
}

// Auth returns the middleware that requires a valid access token and puts the
// authenticated scope on the request context.
func (k *Kit) Auth() gin.HandlerFunc { return k.middleware.AuthMiddleware() }

// Can returns the middleware that requires the authenticated user to hold the
// (resource, action) permission. Superadmin bypasses it. Use it after Auth.
func (k *Kit) Can(resource, action string) gin.HandlerFunc {
	return k.middleware.PermissionMiddleware(resource, action)
}

// Role returns the middleware that requires the authenticated user to have one
// of the allowed roles. Superadmin bypasses it. Use it after Auth.
func (k *Kit) Role(allowed ...string) gin.HandlerFunc {
	return k.middleware.RoleMiddleware(allowed...)
}

// Audit returns the audit service.
func (k *Kit) Audit() AuditService { return k.audit }

// AppConfig returns the app-config service.
func (k *Kit) AppConfig() AppConfigService { return k.appConfig }

// IssueAccessToken issues a normal access token for userID, name and role
// through the Kit's own token service, so it passes Auth like one from login.
// It does not check that the user exists; it is meant for tests and tooling.
func (k *Kit) IssueAccessToken(userID, name, role string) (string, error) {
	return k.tokens.Generate(&domainuser.Users{Id: userID, Name: name, Role: role}, "authkit-issued")
}

// ScopeFrom returns the scope stored on ctx. After Auth alone it has the
// identity and role but an empty permission set, so Has is false for every
// non-superadmin; Can loads the user's permissions into the scope.
func ScopeFrom(ctx context.Context) Scope { return authscope.FromContext(ctx) }
