package shared

import (
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"

	"github.com/gin-gonic/gin"
)

type AuditWriter struct {
	Service AuditService
	Scope   string
}

func NewAuditWriter(service AuditService, scope string) AuditWriter {
	return AuditWriter{Service: service, Scope: scope}
}

// WriteAudit stores event and only logs a failure: use it where losing the
// record must not fail the request.
func (w AuditWriter) WriteAudit(ctx *gin.Context, event domainaudit.AuditEvent) {
	if err := w.WriteAuditStrict(ctx, event); err != nil {
		logus.LogContextf(ctx, logus.LevelWarn, "[%s][Audit]; failed to store audit trail: %v", w.Scope, err)
	}
}

// WriteAuditStrict stores event and returns the storage error, for actions that
// must not go unrecorded (impersonation, RBAC changes). With no audit service
// configured there is nothing to fail and it returns nil.
func (w AuditWriter) WriteAuditStrict(ctx *gin.Context, event domainaudit.AuditEvent) error {
	if w.Service == nil {
		return nil
	}

	scopeData := domainauth.FromContext(ctx.Request.Context())
	if event.ActorUserID == "" && scopeData.ActorUserID() != "" {
		event.ActorUserID = scopeData.ActorUserID()
	}
	if event.ActorRole == "" && scopeData.ActorRole() != "" {
		event.ActorRole = scopeData.ActorRole()
	}
	event.RequestID = gokit.RequestID(ctx).String()
	event.IPAddress = ctx.ClientIP()
	event.UserAgent = ctx.GetHeader("User-Agent")
	event.Metadata = MergeMetadata(event.Metadata, GetImpersonationMetadata(ctx))

	return w.Service.Store(ctx.Request.Context(), event)
}
