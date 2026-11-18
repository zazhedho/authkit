package authkit

import (
	"context"

	"github.com/gin-gonic/gin"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	"github.com/zazhedho/authkit/internal/handlers/http/middleware"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	"github.com/zazhedho/authkit/internal/infrastructure/mailer"
	interfaceappconfig "github.com/zazhedho/authkit/internal/interfaces/appconfig"
	interfaceaudit "github.com/zazhedho/authkit/internal/interfaces/audit"
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
type AuditService = interfaceaudit.ServiceAuditInterface

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
	// RoleMember is the member role.
	RoleMember = domainuser.RoleMember
	// RoleViewer is the default role of public registrations.
	RoleViewer = domainuser.RoleViewer
)

// Mailer sends both registration OTP and password reset emails.
type Mailer interface {
	mailer.Sender
	mailer.PasswordResetSender
}

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
type AppConfigService = interfaceappconfig.ServiceAppConfigInterface
