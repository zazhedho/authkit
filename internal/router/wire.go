package router

import (
	"fmt"
	"time"

	"github.com/zazhedho/authkit/internal/config"
	httpappconfig "github.com/zazhedho/authkit/internal/handlers/http/appconfig"
	httpaudit "github.com/zazhedho/authkit/internal/handlers/http/audit"
	httpmenu "github.com/zazhedho/authkit/internal/handlers/http/menu"
	"github.com/zazhedho/authkit/internal/handlers/http/middleware"
	httppermission "github.com/zazhedho/authkit/internal/handlers/http/permission"
	httprole "github.com/zazhedho/authkit/internal/handlers/http/role"
	httpsession "github.com/zazhedho/authkit/internal/handlers/http/session"
	httpuser "github.com/zazhedho/authkit/internal/handlers/http/user"
	"github.com/zazhedho/authkit/internal/infrastructure/async"
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

const (
	// asyncLimit caps the mail sends running after their responses.
	asyncLimit   = 16
	asyncTimeout = 30 * time.Second
)

// Core is the assembled kit: the Deps the modules mount from, plus the pieces
// the root facade exposes directly.
type Core struct {
	Deps       module.Deps
	Tokens     *token.Tokens
	Middleware *middleware.Middleware
	Users      httpuser.Service
	Async      *async.Runner
	Audit      AuditList
	AppConfig  AppConfigList
}

// Wire builds every repository, service and handler without touching the
// database. It is one function, not a wire.go per module, because modules share
// services (audit, permission invalidator, sessions).
func Wire(cfg config.Config) (*Core, error) {
	tokens, err := token.New(token.Config{
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

	// Without Redis: no limiters or sessions, and OTP/reset get nil deps. With
	// Redis but no Mailer only the limiters and sessions are active.
	var (
		loginLimiter      ratelimit.LoginLimiter
		identifierLimiter ratelimit.LoginLimiter
		sessionSvc        httpuser.SessionService // stays a nil interface without Redis
		sessionRevoker    serviceuser.SessionRevoker
		sessionIndex      middleware.SessionIndex
		sessionHdlr       *httpsession.Handler
		otpSvc            httpuser.OTPService   // nil interface until Redis and a Mailer exist
		resetSvc          httpuser.ResetService // likewise
	)
	if cfg.Redis != nil {
		loginLimiter = ratelimit.NewRedisLoginLimiter(cfg.Redis, cfg.Login.Limit, cfg.Login.Window, cfg.Login.BlockDuration)
		identifierLimiter = ratelimit.NewRedisBackoffLimiter(cfg.Redis, cfg.Login.Limit, cfg.Login.Window, cfg.Login.BlockDuration)
		sessionRepo := repositorysession.NewRepository(cfg.Redis)
		sessions := servicesession.NewService(sessionRepo, cfg.RefreshTokenTTL)
		sessionSvc, sessionRevoker, sessionIndex = sessions, sessions, sessionRepo
		sessionHdlr = httpsession.New(sessions, auditSvc)
		if m := config.OTPSender(cfg); m != nil {
			otpSvc = serviceotp.NewService(repositoryotp.NewRepository(cfg.Redis), m, serviceotp.Config(cfg.OTP))
		}
		if m := config.ResetSender(cfg); m != nil {
			resetSvc = servicereset.NewService(repositoryreset.NewRepository(cfg.Redis), m, servicereset.Config(cfg.Reset))
		}
	}

	userSvc := serviceuser.NewService(userRepo, blacklistRepo, roleRepo, permissionRepo, serviceuser.Options{
		Tokens:          tokens,
		DefaultRole:     cfg.DefaultRole,
		GoogleClientIDs: cfg.GoogleClientIDs,
		PhoneLogin:      cfg.PhoneLogin,
		GoogleVerifier:  verifyGoogle,
		PermissionCache: invalidator,
		Sessions:        sessionRevoker,
	})

	// One cache serves permission sets and auth states.
	cache := cachepermission.New(cfg.Redis)
	authMiddleware, err := middleware.New(middleware.Dependencies{
		BlacklistRepo:      blacklistRepo,
		PermissionRepo:     permissionRepo,
		PermissionCache:    cache,
		Tokens:             tokens,
		PermissionCacheTTL: cfg.PermissionCacheTTL,
		Users:              userRepo,
		StateCache:         cache,
		Sessions:           sessionIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("authkit: middleware: %w", err)
	}
	runner := async.New(asyncLimit, asyncTimeout)

	return &Core{
		Tokens:     tokens,
		Middleware: authMiddleware,
		Users:      userSvc,
		Async:      runner,
		Audit:      auditSvc,
		AppConfig:  appConfigSvc,
		Deps: module.Deps{
			Auth:          authMiddleware.AuthMiddleware(),
			Can:           authMiddleware.PermissionMiddleware,
			RegisterLimit: registerRateLimit(cfg),
			AuthLimit:     authRateLimit(cfg),
			User: httpuser.New(userSvc, sessionSvc, loginLimiter, auditSvc, httpuser.Options{
				AppConfigService:  appConfigSvc,
				OTPService:        otpSvc,
				ResetService:      resetSvc,
				Tokens:            tokens,
				Async:             runner,
				IdentifierLimiter: identifierLimiter,
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
