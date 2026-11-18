package session

import (
	"fmt"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	sessionAuthenticationRequiredMessage = "User is not authenticated. Please login again."
	failedRevokeSessionMessage           = "Failed to revoke a login session"
)

type Handler struct {
	Service Service
	httpshared.AuditWriter
}

func New(s Service, auditService httpshared.AuditService) *Handler {
	return &Handler{
		Service:     s,
		AuditWriter: httpshared.NewAuditWriter(auditService, "SessionHandler"),
	}
}

func (h *Handler) GetActiveSessions(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[SessionHandler][GetActiveSessions]"
	reqCtx := ctx.Request.Context()

	scope := domainauth.FromContext(reqCtx)
	if scope.UserID == "" {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; userId not found in context", logPrefix))
		res := gokit.Unauthorized(logId, sessionAuthenticationRequiredMessage)
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	token, _ := ctx.Get("token")
	currentSession, err := h.Service.GetSessionByToken(reqCtx, token.(string))
	currentSessionID := ""
	if err == nil && currentSession != nil {
		currentSessionID = currentSession.SessionID
	}

	sessions, err := h.Service.GetUserSessions(reqCtx, scope.UserID, currentSessionID)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetUserSessions; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	res := gokit.Response(http.StatusOK, "success", logId, map[string]any{
		"sessions": sessions,
		"total":    len(sessions),
	})
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) RevokeSession(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[SessionHandler][RevokeSession]"
	reqCtx := ctx.Request.Context()

	sessionID := ctx.Param("session_id")
	if sessionID == "" {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "session",
			Status:       domainaudit.StatusFailed,
			Message:      failedRevokeSessionMessage,
			ErrorMessage: "Session ID is required",
		})
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = "session_id is required"
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	scope := domainauth.FromContext(reqCtx)
	if scope.UserID == "" {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; userId not found in context", logPrefix))
		res := gokit.Unauthorized(logId, sessionAuthenticationRequiredMessage)
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	session, err := h.Service.GetSessionBySessionID(reqCtx, sessionID)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "session",
			ResourceID:   sessionID,
			Status:       domainaudit.StatusFailed,
			Message:      failedRevokeSessionMessage,
			ErrorMessage: "The requested session was not found",
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetSessionBySessionID; Error: %+v", logPrefix, err))
		res := gokit.Response(http.StatusNotFound, gokit.MsgSomethingWrong, logId, nil)
		res.Error = "session not found"
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	if session.UserID != scope.UserID {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "session",
			ResourceID:   sessionID,
			Status:       domainaudit.StatusFailed,
			Message:      "Blocked unauthorized session revocation",
			ErrorMessage: "The session belongs to another user",
			AfterData: map[string]any{
				"session_user_id": session.UserID,
			},
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; unauthorized session revocation attempt", logPrefix))
		res := gokit.Forbidden(logId, gokit.MsgAccessDenied)
		ctx.JSON(http.StatusForbidden, res)
		return
	}

	if err := h.Service.DestroySession(reqCtx, sessionID); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "session",
			ResourceID:   sessionID,
			Status:       domainaudit.StatusFailed,
			Message:      failedRevokeSessionMessage,
			ErrorMessage: err.Error(),
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.DestroySession; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "session",
		ResourceID: sessionID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Revoked a login session",
	})

	res := gokit.Response(http.StatusOK, "Session revoked successfully", logId, nil)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) RevokeAllOtherSessions(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[SessionHandler][RevokeAllOtherSessions]"
	reqCtx := ctx.Request.Context()

	scope := domainauth.FromContext(reqCtx)
	if scope.UserID == "" {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; userId not found in context", logPrefix))
		res := gokit.Unauthorized(logId, sessionAuthenticationRequiredMessage)
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	token, _ := ctx.Get("token")
	currentSession, err := h.Service.GetSessionByToken(reqCtx, token.(string))
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "session",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to revoke other login sessions",
			ErrorMessage: "Could not identify the current session",
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetSessionByToken; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	if err := h.Service.DestroyOtherSessions(reqCtx, scope.UserID, currentSession.SessionID); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "session",
			ResourceID:   currentSession.SessionID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to revoke other login sessions",
			ErrorMessage: err.Error(),
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.DestroyOtherSessions; Error: %+v", logPrefix, err))
		res := gokit.InternalServerError(logId)
		ctx.JSON(http.StatusInternalServerError, res)
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "session",
		ResourceID: currentSession.SessionID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Revoked all other login sessions",
	})

	res := gokit.Response(http.StatusOK, "All other sessions revoked successfully", logId, nil)
	ctx.JSON(http.StatusOK, res)
}
