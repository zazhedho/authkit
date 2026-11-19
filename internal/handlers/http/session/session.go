package session

import (
	"net/http"

	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	logID := gokit.RequestID(ctx)
	logPrefix := "[SessionHandler][GetActiveSessions]"
	reqCtx := ctx.Request.Context()

	userID, ok := requireUserID(ctx, logID, logPrefix)
	if !ok {
		return
	}

	token, _ := ctx.Get("token")
	currentSession, err := h.Service.GetSessionByToken(reqCtx, token.(string))
	currentSessionID := ""
	if err == nil && currentSession != nil {
		currentSessionID = currentSession.SessionID
	}

	sessions, err := h.Service.GetUserSessions(reqCtx, userID, currentSessionID)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.GetUserSessions; Error: %+v", logPrefix, err)
		httpshared.RespondInternalError(ctx, logID)
		return
	}

	res := gokit.Response(http.StatusOK, "success", logID, map[string]any{
		"sessions": sessions,
		"total":    len(sessions),
	})
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) RevokeSession(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
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
		res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, "session_id is required")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	userID, ok := requireUserID(ctx, logID, logPrefix)
	if !ok {
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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.GetSessionBySessionID; Error: %+v", logPrefix, err)
		res := gokit.ErrorResponse(http.StatusNotFound, gokit.MsgSomethingWrong, logID, "session not found")
		ctx.JSON(http.StatusNotFound, res)
		return
	}

	if session.UserID != userID {
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
		logus.LogContextf(ctx, logus.LevelError, "%s; unauthorized session revocation attempt", logPrefix)
		res := gokit.Forbidden(logID, gokit.MsgAccessDenied)
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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.DestroySession; Error: %+v", logPrefix, err)
		httpshared.RespondInternalError(ctx, logID)
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "session",
		ResourceID: sessionID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Revoked a login session",
	})

	res := gokit.Response(http.StatusOK, "Session revoked successfully", logID, nil)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) RevokeAllOtherSessions(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[SessionHandler][RevokeAllOtherSessions]"
	reqCtx := ctx.Request.Context()

	userID, ok := requireUserID(ctx, logID, logPrefix)
	if !ok {
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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.GetSessionByToken; Error: %+v", logPrefix, err)
		httpshared.RespondInternalError(ctx, logID)
		return
	}

	if err := h.Service.DestroyOtherSessions(reqCtx, userID, currentSession.SessionID); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "session",
			ResourceID:   currentSession.SessionID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to revoke other login sessions",
			ErrorMessage: err.Error(),
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.DestroyOtherSessions; Error: %+v", logPrefix, err)
		httpshared.RespondInternalError(ctx, logID)
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "session",
		ResourceID: currentSession.SessionID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Revoked all other login sessions",
	})

	res := gokit.Response(http.StatusOK, "All other sessions revoked successfully", logID, nil)
	ctx.JSON(http.StatusOK, res)
}

// requireUserID returns the authenticated user's id. When the request has no
// user, the 401 response is already written and ok is false.
func requireUserID(ctx *gin.Context, logID uuid.UUID, logPrefix string) (userID string, ok bool) {
	userID = domainauth.FromContext(ctx.Request.Context()).UserID
	if userID == "" {
		logus.LogContextf(ctx, logus.LevelError, "%s; userId not found in context", logPrefix)
		ctx.JSON(http.StatusUnauthorized, gokit.Unauthorized(logID, sessionAuthenticationRequiredMessage))
		return "", false
	}
	return userID, true
}
