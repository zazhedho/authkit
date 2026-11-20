package user

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"
)

// refreshRevokedError is the public message for every revoked refresh token.
const refreshRevokedError = "refresh token has been revoked"

// refreshFlow carries one refresh-token request through its steps. A step
// writes its own error response and returns false when the request is over.
type refreshFlow struct {
	h         *Handler
	ctx       *gin.Context
	logID     uuid.UUID
	logPrefix string
	token     string
	claims    map[string]any
	userID    string
	role      string
}

func (f *refreshFlow) reject(publicError string, event domainaudit.AuditEvent) {
	f.h.rejectRefresh(f.ctx, f.logID, publicError, event)
}

func (f *refreshFlow) fail(step string, err error, event domainaudit.AuditEvent) {
	f.h.failRefresh(f.ctx, f.logID, f.logPrefix, step, err, event)
}

// verifyToken checks the presented token is a valid refresh token.
func (f *refreshFlow) verifyToken() bool {
	claims, err := f.h.Tokens.Claims(f.token)
	if err != nil {
		f.reject("invalid or expired refresh token", domainaudit.AuditEvent{
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token is invalid or expired",
		})
		return false
	}
	f.claims = claims
	f.userID = gokit.InterfaceString(claims["user_id"])
	f.role = gokit.InterfaceString(claims["role"])
	if !strings.EqualFold(gokit.InterfaceString(claims["token_type"]), "refresh") {
		f.reject("invalid token type", domainaudit.AuditEvent{
			ActorUserID:  f.userID,
			ActorRole:    f.role,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The provided token is not a refresh token",
		})
		return false
	}
	return true
}

// checkReplay guards against a reused refresh token. With sessions the session
// index is the one replay mechanism: a rotated token that comes back revokes
// the whole session. Without sessions the blacklist claims each token once.
func (f *refreshFlow) checkReplay() (*domainsession.Session, bool) {
	if f.h.SessionSvc == nil {
		return nil, f.checkBlacklist()
	}
	return f.lookupSession()
}

func (f *refreshFlow) lookupSession() (*domainsession.Session, bool) {
	session, err := f.h.SessionSvc.GetSessionByRefreshToken(f.ctx.Request.Context(), f.token)
	if err == nil {
		return session, true
	}
	message := "No active session was found for the refresh token"
	if errors.Is(err, domainsession.ErrRefreshReused) {
		message = "A rotated refresh token was presented again; the session was revoked"
	} else if !errors.Is(err, domainsession.ErrNotFound) {
		f.fail("SessionSvc.GetSessionByRefreshToken", err, domainaudit.AuditEvent{
			ActorUserID: f.userID, ActorRole: f.role, Message: "Failed to look up the login session",
		})
		return nil, false
	}
	f.reject("session not found for refresh token", domainaudit.AuditEvent{
		ActorUserID: f.userID, ActorRole: f.role, ResourceID: f.userID,
		Message: failedRenewLoginSessionMessage, ErrorMessage: message,
	})
	return nil, false
}

func (f *refreshFlow) checkBlacklist() bool {
	revoked, err := f.h.Service.IsTokenRevoked(f.ctx.Request.Context(), f.token)
	if err != nil {
		f.fail("BlacklistRepo.ExistsByToken", err, domainaudit.AuditEvent{
			ActorUserID: f.userID,
			ActorRole:   f.role,
			Message:     "Failed to validate login session renewal",
		})
		return false
	}
	if revoked {
		f.reject(refreshRevokedError, domainaudit.AuditEvent{
			ActorUserID:  f.userID,
			ActorRole:    f.role,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token has already been revoked",
		})
		return false
	}
	return true
}

// loadUser returns the token owner, refusing a token issued before the
// account's tokens were revoked.
func (f *refreshFlow) loadUser() (domainuser.Users, bool) {
	user, err := f.h.Service.GetUserByID(f.ctx.Request.Context(), f.userID)
	if err != nil {
		f.h.auditRefreshFailure(f.ctx, domainaudit.AuditEvent{
			ActorUserID:  f.userID,
			ActorRole:    f.role,
			ResourceID:   f.userID,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The token owner user account was not found",
		})
		statusCode := http.StatusInternalServerError
		if httpshared.IsNotFound(err) {
			statusCode = http.StatusNotFound
		}
		res := gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, f.logID, userNotFoundMessage)
		f.ctx.JSON(statusCode, res)
		return user, false
	}
	if user.TokensValidAfter != nil && domainauth.RevokedBy(f.claims, *user.TokensValidAfter) {
		f.reject(refreshRevokedError, domainaudit.AuditEvent{
			ActorUserID:  f.userID,
			ActorRole:    user.Role,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token was issued before the account's tokens were revoked",
		})
		return user, false
	}
	return user, true
}

// claimToken blacklists the old refresh token when there are no sessions: the
// blacklist has a unique key, so of two concurrent refreshes only one passes.
func (f *refreshFlow) claimToken(user domainuser.Users) bool {
	if f.h.SessionSvc != nil {
		return true
	}
	err := f.h.Service.LogoutUser(f.ctx.Request.Context(), f.token)
	if err == nil {
		return true
	}
	if errors.Is(err, domainauth.ErrDuplicate) {
		f.reject(refreshRevokedError, domainaudit.AuditEvent{
			ActorUserID:  f.userID,
			ActorRole:    user.Role,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token was already used",
		})
		return false
	}
	f.fail("Service.LogoutUser(refresh)", err, f.userEvent(user, "Failed to revoke previous login session token"))
	return false
}

// userEvent is the audit event for an internal failure while renewing user's session.
func (f *refreshFlow) userEvent(user domainuser.Users, message string) domainaudit.AuditEvent {
	return domainaudit.AuditEvent{
		ActorUserID: f.userID,
		ActorRole:   user.Role,
		ResourceID:  f.userID,
		Message:     message,
	}
}

// issueTokens mints the new access and refresh tokens.
func (f *refreshFlow) issueTokens(user domainuser.Users) (accessToken, refreshToken string, ok bool) {
	accessToken, err := f.h.Tokens.Generate(user.ID, user.Name, user.Role, issuedAfter(user))
	if err != nil {
		f.fail("GenerateJwtWithClaims", err, f.userEvent(user, "Failed to issue a new access token"))
		return "", "", false
	}
	refreshToken, err = f.h.Tokens.GenerateRefresh(user.ID, user.Name, user.Role, issuedAfter(user))
	if err != nil {
		f.fail("GenerateRefreshJwt", err, f.userEvent(user, "Failed to issue a new refresh token"))
		return "", "", false
	}
	return accessToken, refreshToken, true
}

// rotateSession swaps the session's tokens, ending the session instead when it
// has passed its absolute lifetime. It does nothing without a session.
func (f *refreshFlow) rotateSession(session *domainsession.Session, user domainuser.Users, accessToken, refreshToken string) bool {
	if session == nil {
		return true
	}
	reqCtx := f.ctx.Request.Context()
	refreshExpAt, withinCap := f.h.sessionExpiry(session.LoginAt)
	if !withinCap {
		if destroyErr := f.h.SessionSvc.DestroySession(reqCtx, session.SessionID); destroyErr != nil {
			logus.LogContextf(f.ctx, logus.LevelError, "%s; SessionSvc.DestroySession; ERROR: %s;", f.logPrefix, destroyErr)
		}
		f.reject("session has reached its maximum lifetime", domainaudit.AuditEvent{
			ActorUserID:  f.userID,
			ActorRole:    user.Role,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The session exceeded its absolute lifetime",
		})
		return false
	}
	err := f.h.SessionSvc.RotateSessionTokens(reqCtx, session.SessionID, accessToken, refreshToken, refreshExpAt)
	if err == nil {
		return true
	}
	if errors.Is(err, domainsession.ErrRefreshReused) {
		f.reject(refreshRevokedError, domainaudit.AuditEvent{
			ActorUserID:  f.userID,
			ActorRole:    user.Role,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token was used concurrently; the session was revoked",
		})
		return false
	}
	event := f.userEvent(user, "Failed to rotate login session tokens")
	event.Metadata = map[string]any{"session_id": session.SessionID}
	f.fail("SessionSvc.RotateSessionTokens", err, event)
	return false
}
