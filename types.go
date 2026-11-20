package authkit

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"

	"github.com/zazhedho/authkit/internal/config"
	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoappconfig "github.com/zazhedho/authkit/internal/dto/appconfig"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	"github.com/zazhedho/authkit/internal/handlers/http/middleware"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	"github.com/zazhedho/authkit/internal/infrastructure/mailer"
)

// Scope is the authenticated identity of a request: user, role and the
// permission set loaded by Can. Read it with ScopeFrom.
type Scope = domainauth.Scope

// NewScope builds a Scope for userID, username and role holding permissions,
// each written as "resource:action". It is meant for tests and tooling.
func NewScope(userID, username, role string, permissions []string) Scope {
	return domainauth.New(userID, username, role, permissions)
}

// WithScope returns a copy of ctx that carries scope, so ScopeFrom returns it.
func WithScope(ctx context.Context, scope Scope) context.Context {
	return domainauth.WithContext(ctx, scope)
}

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

// RequestLogger returns a gin middleware that logs every request with its
// request ID, status and latency.
func RequestLogger() gin.HandlerFunc { return middleware.RequestLogger() }

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

// OTPMailer sends registration OTP emails.
type OTPMailer = config.OTPMailer

// ResetMailer sends password reset emails.
type ResetMailer = config.ResetMailer

// Mailer sends both registration OTP and password reset emails.
type Mailer = config.Mailer

// AuditTrailResponse is one audit trail entry as the audit routes and
// AuditService return it.
type AuditTrailResponse = dtoaudit.AuditTrailResponse

// AppConfig is one app-config entry (a feature flag or setting).
type AppConfig = domainappconfig.AppConfig

// UpdateAppConfig is the request body that updates an app-config entry.
type UpdateAppConfig = dtoappconfig.UpdateAppConfig

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
