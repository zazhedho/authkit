package auditwriter

import (
	"fmt"
	"github.com/zazhedho/authkit/internal/authscope"
	"github.com/zazhedho/authkit/internal/authutil"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	interfaceaudit "github.com/zazhedho/authkit/internal/interfaces/audit"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	"github.com/gin-gonic/gin"
)

type AuditWriter struct {
	Service interfaceaudit.ServiceAuditInterface
	Scope   string
}

func NewAuditWriter(service interfaceaudit.ServiceAuditInterface, scope string) AuditWriter {
	return AuditWriter{Service: service, Scope: scope}
}

func (w AuditWriter) WriteAudit(ctx *gin.Context, event domainaudit.AuditEvent) {
	if w.Service == nil {
		return
	}

	scopeData := authscope.FromContext(ctx.Request.Context())
	if event.ActorUserID == "" && scopeData.ActorUserID() != "" {
		event.ActorUserID = scopeData.ActorUserID()
	}
	if event.ActorRole == "" && scopeData.ActorRole() != "" {
		event.ActorRole = scopeData.ActorRole()
	}
	event.RequestID = gokit.GetRequestID(ctx)
	event.IPAddress = ctx.ClientIP()
	event.UserAgent = ctx.GetHeader("User-Agent")
	event.Metadata = gokit.MergeMetadata(event.Metadata, authutil.GetImpersonationMetadata(ctx))

	if err := w.Service.Store(ctx.Request.Context(), event); err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("[%s][Audit]; failed to store audit trail: %v", w.Scope, err))
	}
}
