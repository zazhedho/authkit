package shared

import (
	"fmt"

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

func (w AuditWriter) WriteAudit(ctx *gin.Context, event domainaudit.AuditEvent) {
	if w.Service == nil {
		return
	}

	scopeData := domainauth.FromContext(ctx.Request.Context())
	if event.ActorUserID == "" && scopeData.ActorUserID() != "" {
		event.ActorUserID = scopeData.ActorUserID()
	}
	if event.ActorRole == "" && scopeData.ActorRole() != "" {
		event.ActorRole = scopeData.ActorRole()
	}
	event.RequestID = gokit.GetRequestID(ctx)
	event.IPAddress = ctx.ClientIP()
	event.UserAgent = ctx.GetHeader("User-Agent")
	event.Metadata = gokit.MergeMetadata(event.Metadata, GetImpersonationMetadata(ctx))

	if err := w.Service.Store(ctx.Request.Context(), event); err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("[%s][Audit]; failed to store audit trail: %v", w.Scope, err))
	}
}
