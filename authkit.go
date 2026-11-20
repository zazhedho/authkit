// Package authkit provides users, sessions, RBAC, audit and app config for gin
// services: build a Config, New, Kit.Migrate, Kit.Mount. Only ConfigFromEnv
// reads the environment.
//
// This file is the whole public surface except the configuration (config.go):
// aliases, constants and one-line wrappers. The logic lives under internal/.
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
	httpuser "github.com/zazhedho/authkit/internal/handlers/http/user"
	"github.com/zazhedho/authkit/internal/infrastructure/async"
	"github.com/zazhedho/authkit/internal/infrastructure/mailer"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	"github.com/zazhedho/authkit/internal/migrate"
	"github.com/zazhedho/authkit/internal/router"
	"github.com/zazhedho/authkit/internal/router/module"
)

// ---- The kit ----

// Kit is the assembled users, auth and RBAC module. Build it once with New and
// mount its routes with Mount; it is safe for concurrent use after New returns.
type Kit struct {
	cfg Config

	tokens     *token.Tokens
	middleware *middleware.Middleware
	deps       module.Deps

	async     *async.Runner
	users     httpuser.Service // kept for white-box wiring tests
	audit     AuditService
	appConfig AppConfigService
}

// New validates cfg (after defaults) and wires everything without touching the
// database. Nil Redis or Mailer is allowed; dependent features become inert (see README).
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
		async: core.Async, users: core.Users, audit: core.Audit, appConfig: core.AppConfig,
	}, nil
}

// Mount registers all users, auth and RBAC routes on r (e.g. engine.Group("/api")).
// Session routes need Redis. Call once per Kit and group: gin panics on duplicates.
func (k *Kit) Mount(r gin.IRouter) error { return router.Mount(r, k.deps) }

// Close waits, bounded by ctx, for the background mail sends to finish. Call
// it on shutdown after the HTTP server has stopped.
func (k *Kit) Close(ctx context.Context) error { return k.async.Wait(ctx) }

// Migrate applies pending migrations; safe on every start (instances serialize
// on an advisory lock). ctx bounds the connection checkout only; see README, Migrations.
func (k *Kit) Migrate(ctx context.Context) error { return migrate.Up(ctx, k.cfg.DB) }

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
	return k.tokens.GenerateNoSession(userID, name, role, time.Time{})
}

// ---- Request scope ----

// Scope is the authenticated identity of a request: user, role and the
// permission set loaded by Can. Read it with ScopeFrom.
type Scope = domainauth.Scope

// ScopeFrom returns the scope on ctx. After Auth alone the permission set is
// empty (Has is false for non-superadmins); Can or LoadPermissions loads it.
func ScopeFrom(ctx context.Context) Scope { return domainauth.FromContext(ctx) }

// WithScope returns a copy of ctx that carries scope, so ScopeFrom returns it.
func WithScope(ctx context.Context, scope Scope) context.Context {
	return domainauth.WithContext(ctx, scope)
}

// NewScope builds a Scope for userID, username and role holding permissions,
// each written as "resource:action". It is meant for tests and tooling.
func NewScope(userID, username, role string, permissions []string) Scope {
	return domainauth.New(userID, username, role, permissions)
}

// RequestLogger returns a gin middleware that logs every request with its
// request ID, status and latency.
func RequestLogger() gin.HandlerFunc { return middleware.RequestLogger() }

// ---- Roles ----

// Built-in role names.
const (
	// RoleSuperAdmin bypasses every permission and role check.
	RoleSuperAdmin = domainuser.RoleSuperAdmin
	// RoleAdmin is the administrator role.
	RoleAdmin = domainuser.RoleAdmin
	// RoleStaff is the staff role.
	RoleStaff = domainuser.RoleStaff
	// RoleViewer is the default role of public registrations.
	RoleViewer = domainuser.RoleViewer
)

// ---- Audit ----

// AuditEvent describes one audit trail entry written through an AuditService
// or an AuditWriter.
type AuditEvent = domainaudit.AuditEvent

// Audit actions for AuditEvent.Action.
const (
	// ActionCreate records the creation of a resource.
	ActionCreate = domainaudit.ActionCreate
	// ActionUpdate records the modification of a resource.
	ActionUpdate = domainaudit.ActionUpdate
	// ActionDelete records the deletion of a resource.
	ActionDelete = domainaudit.ActionDelete
	// ActionAssign records an assignment, such as permissions to a role.
	ActionAssign = domainaudit.ActionAssign
	// ActionLogin records a login.
	ActionLogin = domainaudit.ActionLogin
	// ActionLogout records a logout.
	ActionLogout = domainaudit.ActionLogout
	// ActionRefresh records a token refresh.
	ActionRefresh = domainaudit.ActionRefresh
)

// Audit statuses for AuditEvent.Status.
const (
	// StatusSuccess marks an audited operation that succeeded.
	StatusSuccess = domainaudit.StatusSuccess
	// StatusFailed marks an audited operation that failed.
	StatusFailed = domainaudit.StatusFailed
)

// AuditTrailResponse is one audit trail entry as the audit routes and
// AuditService return it.
type AuditTrailResponse = dtoaudit.AuditTrailResponse

// AuditService stores and reads audit trail entries. Kit.Audit returns one.
type AuditService interface {
	Store(ctx context.Context, req AuditEvent) error
	GetAll(ctx context.Context, params gokit.BaseParams) ([]AuditTrailResponse, int64, error)
	GetByID(ctx context.Context, id string) (AuditTrailResponse, error)
}

// AuditWriter writes audit events from gin handlers, filling the actor from
// the request scope. Build one with NewAuditWriter.
type AuditWriter = httpshared.AuditWriter

// NewAuditWriter returns an AuditWriter that stores events through service and
// tags failures it logs with scope (a short name for the calling component).
func NewAuditWriter(service AuditService, scope string) AuditWriter {
	return httpshared.NewAuditWriter(service, scope)
}

// ---- App config ----

// AppConfig is one app-config entry (a feature flag or setting).
type AppConfig = domainappconfig.AppConfig

// UpdateAppConfig is the request body that updates an app-config entry.
type UpdateAppConfig = dtoappconfig.UpdateAppConfig

// AppConfigService reads and updates the app-config entries (feature flags and
// settings). Kit.AppConfig returns one.
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

// OTPMailer sends registration OTP emails.
type OTPMailer = config.OTPMailer

// ResetMailer sends password reset emails.
type ResetMailer = config.ResetMailer

// Mailer sends both registration OTP and password reset emails.
type Mailer = config.Mailer

// BrevoConfig is the explicit SMTP configuration for the Brevo mailer. Host,
// Pass and From are required; the remaining fields fall back to defaults.
type BrevoConfig = mailer.BrevoConfig

// NewBrevoMailer validates cfg and returns a Mailer that sends through Brevo
// SMTP. Pass it as Config.Mailer.
func NewBrevoMailer(cfg BrevoConfig) (Mailer, error) {
	sender, err := mailer.NewBrevoSender(cfg)
	if err != nil {
		return nil, err
	}
	return sender, nil
}

// ---- Migrations ----

// MigrationsTable is the version table authkit uses, so it never collides with
// the host project's own golang-migrate table (schema_migrations by default).
const MigrationsTable = migrate.Table

// ErrMigrationsDirty means the version table records a failed migration. Fix the
// database by hand and clear the dirty flag; never delete the record.
var ErrMigrationsDirty = migrate.ErrDirty
