package router

import (
	"fmt"

	"github.com/zazhedho/authkit/internal/config"
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
	"github.com/zazhedho/authkit/internal/router/module"
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

// Core is the assembled kit: the Deps the modules mount from, plus the pieces
// the root facade exposes directly.
type Core struct {
	Deps       module.Deps
	Tokens     *token.Tokens
	Middleware *middleware.Middleware
	Users      httpuser.Service
	Audit      AuditList
	AppConfig  AppConfigList
}

// Wire builds every repository, service and handler from cfg without touching
// the database. cfg must have its defaults applied and be valid. Nil Redis or
// Mailer is allowed; dependent features become inert (see README).
//
// It lives here, not in a wire.go per module like starter-kit, because the
// modules share their services: the audit service feeds every handler, the
// permission invalidator feeds users, roles and permissions, and the session
// service feeds both the user and session modules.
func Wire(cfg config.Config) (*Core, error) {
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
	appConfigCore.SetBoolKeys(cfg.Flags.PublicRegistration, cfg.Flags.RegisterOTP, cfg.Flags.PasswordResetEmail)
	auditSvc := AuditList{auditCore}
	appConfigSvc := AppConfigList{appConfigCore}
	userSvc := serviceuser.NewService(userRepo, blacklistRepo, roleRepo, permissionRepo, serviceuser.Options{
		Tokens:          tokens,
		DefaultRole:     cfg.DefaultRole,
		GoogleClientIDs: cfg.GoogleClientIDs,
		PhoneLogin:      cfg.PhoneLogin,
		GoogleVerifier:  verifyGoogle,
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
		userSvc.Sessions = sessions
		sessionHdlr = httpsession.New(sessions, auditSvc)
		if m := config.OTPSender(cfg); m != nil {
			otpSvc = serviceotp.NewService(repositoryotp.NewRepository(cfg.Redis), m, serviceotp.Config(cfg.OTP))
		}
		if m := config.ResetSender(cfg); m != nil {
			resetSvc = servicereset.NewService(repositoryreset.NewRepository(cfg.Redis), m, servicereset.Config(cfg.Reset))
		}
	}

	authMiddleware := middleware.NewMiddleware(blacklistRepo, permissionRepo, cachepermission.NewCache(cfg.Redis), tokens, cfg.PermissionCacheTTL)
	authMiddleware.Users = userRepo
	authMiddleware.StateCache = cachepermission.NewCache(cfg.Redis)
	if sessionRepo != nil {
		authMiddleware.Sessions = sessionRepo
	}

	return &Core{
		Tokens:     tokens,
		Middleware: authMiddleware,
		Users:      userSvc,
		Audit:      auditSvc,
		AppConfig:  appConfigSvc,
		Deps: module.Deps{
			Auth:          authMiddleware.AuthMiddleware(),
			Can:           authMiddleware.PermissionMiddleware,
			RegisterLimit: registerRateLimit(cfg),
			AuthLimit:     authRateLimit(cfg),
			User: httpuser.New(userSvc, sessionSvc, loginLimiter, auditSvc, httpuser.Options{
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
					FailClosedLimiters: cfg.FailClosedLimiters,
					OTPCooldown:        cfg.OTP.Cooldown,
					ResetCooldown:      cfg.Reset.Cooldown,
					Flags:              httpuser.FlagKeys(cfg.Flags),
				},
			}),
			Role:       httprole.New(servicerole.NewService(roleRepo, permissionRepo, menuRepo, invalidator), auditSvc),
			Permission: httppermission.New(servicepermission.NewService(permissionRepo, invalidator), auditSvc),
			Menu:       httpmenu.New(servicemenu.NewService(menuRepo, permissionRepo), auditSvc),
			AppConfig:  httpappconfig.New(appConfigCore, auditSvc),
			Audit:      httpaudit.New(auditCore),
			Session:    sessionHdlr,
		},
	}, nil
}
