// Package authkit provides users, sessions, RBAC, audit and app config for gin
// services: build a Config, New, Kit.Migrate, Kit.Mount. Only ConfigFromEnv
// reads the environment. The logic lives under internal/.
package authkit

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	"github.com/zazhedho/authkit/internal/config"
	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	"github.com/zazhedho/authkit/internal/handlers/http/middleware"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	"github.com/zazhedho/authkit/internal/infrastructure/async"
	"github.com/zazhedho/authkit/internal/infrastructure/mailer"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	"github.com/zazhedho/authkit/internal/migrate"
	"github.com/zazhedho/authkit/internal/router"
	"github.com/zazhedho/authkit/internal/router/module"
)

// ---- The kit ----

// Kit is safe for concurrent use after New returns.
type Kit struct {
	cfg Config

	tokens     *token.Tokens
	middleware *middleware.Middleware
	deps       module.Deps

	async     *async.Runner
	audit     AuditService
	appConfig AppConfigService
}

// New validates cfg and wires everything without touching the database. A nil
// Redis or mailer is allowed; the features that need them stay inert.
func New(cfg Config) (*Kit, error) {
	cfg = config.WithDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	for _, w := range config.Warnings(cfg) {
		logus.Log(logus.LevelWarn, w)
	}
	core, err := router.Wire(cfg)
	if err != nil {
		return nil, err
	}
	return &Kit{
		cfg: cfg, tokens: core.Tokens, middleware: core.Middleware, deps: core.Deps,
		async: core.Async, audit: core.Audit, appConfig: core.AppConfig,
	}, nil
}

// Mount registers the routes on r and returns every module's error. Call it
// once per group: gin panics on duplicate routes.
func (k *Kit) Mount(r gin.IRouter) error { return router.Mount(r, k.deps) }

// Close waits, bounded by ctx, for background mail sends; call it after the
// HTTP server has stopped.
func (k *Kit) Close(ctx context.Context) error { return k.async.Close(ctx) }

// Migrate is safe on every start: instances serialize on an advisory lock. ctx
// bounds the connection checkout only.
func (k *Kit) Migrate(ctx context.Context) error { return migrate.Up(ctx, k.cfg.DB) }

func (k *Kit) Auth() gin.HandlerFunc { return k.middleware.AuthMiddleware() }

// Can needs Auth before it; the superadmin bypasses it.
func (k *Kit) Can(resource, action string) gin.HandlerFunc {
	return k.middleware.PermissionMiddleware(resource, action)
}

// LoadPermissions never rejects for a missing permission, so a handler can
// branch on Scope.Has ("_any" checks). It needs Auth before it.
func (k *Kit) LoadPermissions() gin.HandlerFunc {
	return k.middleware.LoadPermissionsMiddleware()
}

// Role needs Auth before it; the superadmin bypasses it.
func (k *Kit) Role(allowed ...string) gin.HandlerFunc {
	return k.middleware.RoleMiddleware(allowed...)
}

func (k *Kit) Audit() AuditService { return k.audit }

func (k *Kit) AppConfig() AppConfigService { return k.appConfig }

// IssueAccessToken is for tests and tooling: a session-less token that Auth accepts.
func (k *Kit) IssueAccessToken(userID, name, role string) (string, error) {
	return k.tokens.GenerateNoSession(userID, name, role, time.Time{})
}

// ---- Request scope ----

type Scope = domainauth.Scope

// ScopeFrom has an empty permission set after Auth alone; Can or
// LoadPermissions loads it.
func ScopeFrom(ctx context.Context) Scope { return domainauth.FromContext(ctx) }

// WithScope is for tests and tooling.
func WithScope(ctx context.Context, scope Scope) context.Context {
	return domainauth.WithContext(ctx, scope)
}

// NewScope is for tests and tooling; permissions are written "resource:action".
func NewScope(userID, username, role string, permissions []string) Scope {
	return domainauth.New(userID, username, role, permissions)
}

func RequestLogger() gin.HandlerFunc { return middleware.RequestLogger() }

// ---- Roles ----

// Built-in role names.
const (
	RoleSuperAdmin = domainuser.RoleSuperAdmin
	RoleAdmin      = domainuser.RoleAdmin
	RoleStaff      = domainuser.RoleStaff
	RoleViewer     = domainuser.RoleViewer
)

// ---- Audit ----

type AuditEvent = domainaudit.AuditEvent

// Audit actions for AuditEvent.Action.
const (
	ActionCreate  = domainaudit.ActionCreate
	ActionUpdate  = domainaudit.ActionUpdate
	ActionDelete  = domainaudit.ActionDelete
	ActionAssign  = domainaudit.ActionAssign
	ActionLogin   = domainaudit.ActionLogin
	ActionLogout  = domainaudit.ActionLogout
	ActionRefresh = domainaudit.ActionRefresh
)

// Audit statuses for AuditEvent.Status.
const (
	StatusSuccess = domainaudit.StatusSuccess
	StatusFailed  = domainaudit.StatusFailed
)

type AuditTrailResponse = dtoaudit.AuditTrailResponse

type AuditService interface {
	Store(ctx context.Context, req AuditEvent) error
	GetAll(ctx context.Context, params gokit.BaseParams) ([]AuditTrailResponse, int64, error)
	GetByID(ctx context.Context, id string) (AuditTrailResponse, error)
}

type AuditWriter = httpshared.AuditWriter

// NewAuditWriter tags the failures it logs with scope, a short component name.
func NewAuditWriter(service AuditService, scope string) AuditWriter {
	return httpshared.NewAuditWriter(service, scope)
}

// ---- App config ----

type AppConfig = domainappconfig.AppConfig

type UpdateAppConfig = dtoappconfig.UpdateAppConfig

type AppConfigService interface {
	GetAll(ctx context.Context, params gokit.BaseParams) ([]AppConfig, int64, error)
	GetByID(ctx context.Context, id string) (AppConfig, error)
	GetByKey(ctx context.Context, configKey string) (AppConfig, error)
	Update(ctx context.Context, id string, req UpdateAppConfig) (AppConfig, error)
	GetString(ctx context.Context, configKey string, fallback string) (string, error)
	GetBool(ctx context.Context, configKey string, fallback bool) (bool, error)
	GetInt(ctx context.Context, configKey string, fallback int) (int, error)
	GetDuration(ctx context.Context, configKey string, fallback time.Duration) (time.Duration, error)
	DecodeJSON(ctx context.Context, configKey string, target any) error
	IsEnabled(ctx context.Context, configKey string, fallback bool) (bool, error)
}

// ---- Mail ----

type OTPMailer = config.OTPMailer

type ResetMailer = config.ResetMailer

type Mailer = config.Mailer

// BrevoConfig requires Host, Pass and From; the rest has defaults.
type BrevoConfig = mailer.BrevoConfig

func NewBrevoMailer(cfg BrevoConfig) (Mailer, error) {
	sender, err := mailer.NewBrevoSender(cfg)
	if err != nil {
		return nil, err
	}
	return sender, nil
}

// ---- Migrations ----

// MigrationsTable keeps authkit clear of the host's own golang-migrate table.
const MigrationsTable = migrate.Table

// ErrMigrationsDirty means a migration failed half way: repair the database by
// hand and clear the dirty flag; never delete the record.
var ErrMigrationsDirty = migrate.ErrDirty
