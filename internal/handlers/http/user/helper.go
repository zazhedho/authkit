package user

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainreset "github.com/zazhedho/authkit/internal/domain/reset"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	publicRegistrationDisabledMessage      = "Public registration is currently disabled."
	registrationOTPNotConfiguredMessage    = "registration OTP service is not configured"
	passwordResetEmailNotConfiguredMessage = "password reset email service is not configured"
	failedRenewLoginSessionMessage         = "Failed to renew login session"
	userNotFoundMessage                    = "user not found"
)

func (h *Handler) respondTooManyLoginAttempts(ctx *gin.Context, logID uuid.UUID, ttl time.Duration) {
	if ttl > 0 {
		ctx.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))
	}

	message := "Too many login attempts. Please try again later."
	if ttl > 0 {
		message = fmt.Sprintf("Too many login attempts. Try again in %d seconds.", int(ttl.Seconds()))
	}

	res := gokit.ErrorResponse(http.StatusTooManyRequests, gokit.MsgSomethingWrong, logID, message)
	ctx.AbortWithStatusJSON(http.StatusTooManyRequests, res)
}

func (h *Handler) respondThrottle(ctx *gin.Context, logID uuid.UUID, ttl time.Duration, message string) {
	if ttl > 0 {
		ctx.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))
	}

	if message == "" {
		message = "Too many requests. Please try again later."
	}

	res := gokit.ErrorResponse(http.StatusTooManyRequests, gokit.MsgSomethingWrong, logID, message)
	ctx.AbortWithStatusJSON(http.StatusTooManyRequests, res)
}

func (h *Handler) registrationConflict(ctx context.Context, email, phone string) (string, string, error) {
	user, err := h.Service.GetUserByEmail(ctx, email)
	if err != nil && !httpshared.IsNotFound(err) {
		return "", "Service.GetUserByEmail", err
	}
	if user.ID != "" {
		return "email already exists", "", nil
	}
	if phone == "" {
		return "", "", nil
	}

	user, err = h.Service.GetUserByPhone(ctx, domainuser.NormalizePhoneTo62(phone))
	if err != nil && !httpshared.IsNotFound(err) {
		return "", "Service.GetUserByPhone", err
	}
	if user.ID != "" {
		return "phone number already exists", "", nil
	}
	return "", "", nil
}

func (h *Handler) rejectBlockedLogin(ctx *gin.Context, logID uuid.UUID, logPrefix, loginIdentifier, normalizedIdentifier string) bool {
	if h.LoginLimiter == nil {
		return false
	}
	blocked, ttl, err := h.LoginLimiter.IsBlocked(ctx.Request.Context(), loginIdentifier)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; LoginLimiter.IsBlocked error: %v", logPrefix, err)
		return false
	}
	if !blocked {
		return false
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionLogin,
		Resource: "auth",
		Status:   domainaudit.StatusFailed,
		Message:  "Login blocked due to too many attempts",
		AfterData: map[string]any{
			"identifier": normalizedIdentifier,
		},
	})
	logus.LogContextf(ctx, logus.LevelWarn, "%s; Too many attempts", logPrefix)
	h.respondTooManyLoginAttempts(ctx, logID, ttl)
	return true
}

func (h *Handler) handleLoginFailure(ctx *gin.Context, logID uuid.UUID, logPrefix, normalizedIdentifier, loginIdentifier string, err error) {
	logus.LogContextf(ctx, logus.LevelError, "%s; Service.LoginUser; ERROR: %s;", logPrefix, err)
	if !httpshared.IsNotFound(err) && err.Error() != ErrHashPassword {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogin,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Login failed due to internal error",
			ErrorMessage: err.Error(),
			AfterData:    map[string]any{"identifier": normalizedIdentifier},
		})
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return
	}

	if h.LoginLimiter != nil {
		blocked, ttl, limiterErr := h.LoginLimiter.RegisterFailure(ctx.Request.Context(), loginIdentifier)
		if limiterErr != nil {
			logus.LogContextf(ctx, logus.LevelError, "%s; LoginLimiter.RegisterFailure error: %v", logPrefix, limiterErr)
		}
		if blocked {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action:   domainaudit.ActionLogin,
				Resource: "auth",
				Status:   domainaudit.StatusFailed,
				Message:  "Login blocked after repeated failures",
				AfterData: map[string]any{
					"identifier": normalizedIdentifier,
				},
			})
			logus.LogContextf(ctx, logus.LevelWarn, "%s; Account temporarily locked after repeated failures", logPrefix)
			h.respondTooManyLoginAttempts(ctx, logID, ttl)
			return
		}
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionLogin,
		Resource: "auth",
		Status:   domainaudit.StatusFailed,
		Message:  "Login failed due to invalid credentials",
		AfterData: map[string]any{
			"identifier": normalizedIdentifier,
		},
	})
	res := gokit.ErrorResponse(http.StatusBadRequest, InvalidCred, logID, MsgCredential)
	ctx.JSON(http.StatusBadRequest, res)
}

func (h *Handler) resetLoginLimiter(ctx *gin.Context, logPrefix, loginIdentifier string) {
	if h.LoginLimiter == nil {
		return
	}
	if err := h.LoginLimiter.Reset(ctx.Request.Context(), loginIdentifier); err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; LoginLimiter.Reset error: %v", logPrefix, err)
	}
}

func (h *Handler) createLoginSession(ctx *gin.Context, reqCtx context.Context, user *domainuser.Users, userErr error, token, refreshToken, logPrefix string) {
	if h.SessionSvc == nil || userErr != nil || refreshToken == "" {
		return
	}
	session, err := h.SessionSvc.CreateSession(reqCtx, user, token, refreshToken, domainsession.RequestMeta{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
	})
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; Failed to create session: %v", logPrefix, err)
		return
	}
	logus.LogContextf(ctx, logus.LevelInfo, "%s; Session created: %s", logPrefix, session.SessionID)
}

func (h *Handler) forgotPasswordByEmail(ctx *gin.Context, req dtouser.ForgotPasswordRequest, logID uuid.UUID, logPrefix string) {
	if h.ResetService == nil {
		res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, passwordResetEmailNotConfiguredMessage)
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}

	reqCtx := ctx.Request.Context()
	normalizedEmail := domainuser.SanitizeEmail(req.Email)
	if data, err := h.Service.GetUserByEmail(reqCtx, normalizedEmail); err == nil && data.ID != "" {
		appName := h.Settings.EmailAppName
		if err := h.ResetService.RequestReset(reqCtx, normalizedEmail, appName); err != nil {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
				Message: "Failed to request password reset email", ErrorMessage: err.Error(),
				AfterData: map[string]any{"email": normalizedEmail},
			})
			if throttle, ok := errors.AsType[*domainreset.ThrottleError](err); ok {
				h.respondThrottle(ctx, logID, throttle.RetryAfter, "Password reset request is throttled. Please try again later.")
				return
			}
			statusCode := http.StatusInternalServerError
			message := "Failed to send password reset email. Please contact support with the log ID."
			if errors.Is(err, domainreset.ErrNotConfigured) || errors.Is(err, domainreset.ErrDeliveryFailed) {
				statusCode = http.StatusServiceUnavailable
				message = "Password reset email service is temporarily unavailable."
			}
			res := gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, message)
			ctx.JSON(statusCode, res)
			return
		}
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusSuccess,
		Message: "Requested password reset email", AfterData: map[string]any{"email": normalizedEmail},
	})
	res := gokit.Response(http.StatusOK, "Password reset instructions sent to your email", logID, map[string]any{
		"cooldown": int(h.Settings.ResetCooldown.Seconds()),
	})
	logus.LogContextf(ctx, logus.LevelInfo, "%s; Password reset instructions sent to email: %s", logPrefix, normalizedEmail)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) resetPasswordByEmail(ctx *gin.Context, req dtouser.ResetPasswordRequest, logID uuid.UUID, logPrefix string) {
	if h.ResetService == nil {
		res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, passwordResetEmailNotConfiguredMessage)
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}
	reqCtx := ctx.Request.Context()
	email, err := h.ResetService.VerifyReset(reqCtx, req.Token)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to verify password reset token", ErrorMessage: err.Error(),
		})
		statusCode := http.StatusBadRequest
		message := "invalid or expired reset token"
		if errors.Is(err, domainreset.ErrNotConfigured) {
			statusCode = http.StatusServiceUnavailable
			message = passwordResetEmailNotConfiguredMessage
		}
		res := gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, message)
		ctx.JSON(statusCode, res)
		return
	}

	userID := ""
	if h.SessionSvc != nil {
		user, err := h.Service.GetUserByEmail(reqCtx, email)
		if err != nil {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
				Message: "Failed to load user for password reset", ErrorMessage: err.Error(),
				AfterData: map[string]any{"email": email},
			})
			statusCode, res := userMutationErrorResponse(logID, err)
			ctx.JSON(statusCode, res)
			return
		}
		userID = user.ID
	}
	if err := h.Service.ResetPasswordByEmail(reqCtx, email, req.NewPassword); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to reset password", ErrorMessage: err.Error(),
			AfterData: map[string]any{"email": email},
		})
		statusCode, res := userMutationErrorResponse(logID, err)
		ctx.JSON(statusCode, res)
		return
	}
	if err := h.revokePasswordResetSessions(reqCtx, userID); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to revoke sessions after password reset", ErrorMessage: err.Error(),
			AfterData: map[string]any{"email": email},
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; SessionSvc.DestroyAllUserSessions; ERROR: %s;", logPrefix, err)
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusSuccess,
		Message: "Reset password success", AfterData: map[string]any{"email": email},
	})
	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, "Password reset successfully", logID, nil))
}

func (h *Handler) isRuntimeConfigEnabled(ctx context.Context, configKey string, fallback bool) (bool, error) {
	if h.AppConfigService == nil {
		return fallback, nil
	}
	return h.AppConfigService.IsEnabled(ctx, configKey, fallback)
}

func (h *Handler) buildAuthTokenResponse(accessToken, refreshToken string) map[string]any {
	data := map[string]any{
		"access_token":     accessToken,
		"token_type":       "Bearer",
		"expires_in_hours": int(h.Settings.AccessTTL.Hours()),
	}

	if refreshToken != "" {
		data["refresh_token"] = refreshToken
		data["refresh_expires_in_hours"] = int(h.Settings.RefreshTTL.Hours())
	}

	return data
}

func userMutationErrorResponse(logID uuid.UUID, err error) (int, *gokit.APIResponse) {
	if httpshared.IsNotFound(err) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, userNotFoundMessage)
	}
	if errors.Is(err, domainuser.ErrDuplicate) {
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logID, "email or phone already exists")
	}

	errMsg := err.Error()
	switch {
	case errMsg == userNotFoundMessage:
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, userNotFoundMessage)
	case errMsg == "invalid or expired token":
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, "invalid or expired reset token")
	case strings.HasPrefix(errMsg, "access denied:"),
		strings.Contains(errMsg, "superadmin"):
		return http.StatusForbidden, gokit.Forbidden(logID, gokit.MsgAccessDenied)
	case strings.Contains(errMsg, "already exists"):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logID, errMsg)
	case strings.HasPrefix(errMsg, "invalid role:"),
		strings.HasPrefix(errMsg, "password must "),
		strings.HasPrefix(errMsg, "new password must "):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, errMsg)
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logID)
	}
}

func impersonationErrorResponse(logID uuid.UUID, err error) (int, *gokit.APIResponse) {
	if httpshared.IsNotFound(err) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, userNotFoundMessage)
	}

	errMsg := err.Error()
	switch {
	case strings.HasPrefix(errMsg, "cannot impersonate"):
		return http.StatusForbidden, gokit.Forbidden(logID, gokit.MsgAccessDenied)
	case strings.HasPrefix(errMsg, "cannot start"),
		strings.HasPrefix(errMsg, "target user id"),
		strings.HasPrefix(errMsg, "original user id"),
		strings.HasPrefix(errMsg, "current session"):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, errMsg)
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logID)
	}
}

// impersonation is the original identity an impersonated token carries.
type impersonation struct {
	userID, username, role string
}

func impersonationFromClaims(claims map[string]any) *impersonation {
	if claims == nil || !httpshared.InterfaceBool(claims["is_impersonated"]) {
		return nil
	}

	return &impersonation{
		userID:   gokit.InterfaceString(claims["original_user_id"]),
		username: gokit.InterfaceString(claims["original_username"]),
		role:     gokit.InterfaceString(claims["original_role"]),
	}
}

func (h *Handler) issueAccessToken(user *domainuser.Users, logID string, imp *impersonation) (string, error) {
	if imp == nil {
		return h.Tokens.Generate(user.ID, user.Name, user.Role, logID)
	}
	return h.Tokens.GenerateImpersonated(user.ID, user.Name, user.Role, logID, imp.userID, imp.username, imp.role)
}

func (h *Handler) issueRefreshToken(user *domainuser.Users, logID string, imp *impersonation) (string, error) {
	if imp == nil {
		return h.Tokens.GenerateRefresh(user.ID, user.Name, user.Role, logID)
	}
	return h.Tokens.GenerateRefreshImpersonated(user.ID, user.Name, user.Role, logID, imp.userID, imp.username, imp.role)
}

// configEnabled reads a runtime flag. When the lookup fails it logs, writes the
// 500 response and returns ok=false.
func (h *Handler) configEnabled(ctx *gin.Context, logID uuid.UUID, logPrefix, key string, fallback bool) (enabled, ok bool) {
	enabled, err := h.isRuntimeConfigEnabled(ctx.Request.Context(), key, fallback)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; Config check ERROR: %s;", logPrefix, err.Error())
		httpshared.RespondInternalError(ctx, logID)
		return false, false
	}
	return enabled, true
}

// registrationOpen reports whether public registration is enabled. When it is
// not, the 500 or 403 response is already written.
func (h *Handler) registrationOpen(ctx *gin.Context, logID uuid.UUID, logPrefix string) bool {
	enabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.PublicRegistration, true)
	if !ok {
		return false
	}
	if !enabled {
		ctx.JSON(http.StatusForbidden, gokit.Forbidden(logID, publicRegistrationDisabledMessage))
		return false
	}
	return true
}

// respondStepFailed logs a failed step and writes the generic 500 response.
func respondStepFailed(ctx *gin.Context, logID uuid.UUID, logPrefix, step string, err error) {
	logus.LogContextf(ctx, logus.LevelError, "%s; %s; ERROR: %s;", logPrefix, step, err)
	httpshared.RespondInternalError(ctx, logID)
}

func respondUserNotFound(ctx *gin.Context, logID uuid.UUID) {
	res := gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, userNotFoundMessage)
	ctx.JSON(http.StatusNotFound, res)
}

// respondUserLookupError answers 404 for a missing user and 500 otherwise.
func respondUserLookupError(ctx *gin.Context, logID uuid.UUID, err error) {
	if httpshared.IsNotFound(err) {
		respondUserNotFound(ctx, logID)
		return
	}
	httpshared.RespondInternalError(ctx, logID)
}

// respondUserMutationError answers 404 for a missing user and the mapped
// mutation response otherwise.
func respondUserMutationError(ctx *gin.Context, logID uuid.UUID, err error) {
	if httpshared.IsNotFound(err) {
		respondUserNotFound(ctx, logID)
		return
	}
	statusCode, res := userMutationErrorResponse(logID, err)
	ctx.JSON(statusCode, res)
}

// userSnapshot is the audit view of a created user.
func userSnapshot(u domainuser.Users) map[string]any {
	return map[string]any{
		"id":    u.ID,
		"name":  u.Name,
		"email": u.Email,
		"phone": u.Phone,
		"role":  u.Role,
	}
}

// auditRefreshFailure records a failed token refresh. The event carries the
// actor, message and error; the action, resource and status are fixed here.
func (h *Handler) auditRefreshFailure(ctx *gin.Context, event domainaudit.AuditEvent) {
	event.Action = domainaudit.ActionRefresh
	event.Resource = "auth_token"
	event.Status = domainaudit.StatusFailed
	h.WriteAudit(ctx, event)
}

// failRefresh audits a refresh that broke on an internal error, logs the step
// and answers 500.
func (h *Handler) failRefresh(ctx *gin.Context, logID uuid.UUID, logPrefix, step string, err error, event domainaudit.AuditEvent) {
	event.ErrorMessage = err.Error()
	h.auditRefreshFailure(ctx, event)
	respondStepFailed(ctx, logID, logPrefix, step, err)
}

// updateUser updates a user's profile and audits the change. The caller has
// already resolved the target id.
func (h *Handler) updateUser(ctx *gin.Context, logID uuid.UUID, logPrefix, id string, req dtouser.Update, failedMessage, successMessage string) {
	reqCtx := ctx.Request.Context()
	before, _ := h.Service.GetUserByID(reqCtx, id)
	data, err := h.Service.Update(reqCtx, httpshared.ActorFrom(reqCtx), id, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      failedMessage,
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.Update; ERROR: %s;", logPrefix, err)
		respondUserMutationError(ctx, logID, err)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "user",
		ResourceID: data.ID,
		Status:     domainaudit.StatusSuccess,
		Message:    successMessage,
		BeforeData: before,
		AfterData:  data,
	})

	res := gokit.Response(http.StatusOK, "User updated successfully", logID, data)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(data))
	ctx.JSON(http.StatusOK, res)
}

// deleteUser deletes a user and audits the removal. The caller has already
// resolved the target id.
func (h *Handler) deleteUser(ctx *gin.Context, logID uuid.UUID, logPrefix, id, failedMessage, successMessage string) {
	reqCtx := ctx.Request.Context()
	before, _ := h.Service.GetUserByID(reqCtx, id)

	if err := h.Service.Delete(reqCtx, id); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "user",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      failedMessage,
			ErrorMessage: err.Error(),
			BeforeData:   before,
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.Delete; ERROR: %s;", logPrefix, err)
		respondUserLookupError(ctx, logID, err)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "user",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    successMessage,
		BeforeData: before,
	})

	res := gokit.Response(http.StatusOK, "User deleted successfully", logID, nil)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Success: User deleted successfully", logPrefix)
	ctx.JSON(http.StatusOK, res)
}

// rejectRefresh audits a refresh the caller is not allowed to make and answers
// 401 with publicError.
func (h *Handler) rejectRefresh(ctx *gin.Context, logID uuid.UUID, publicError string, event domainaudit.AuditEvent) {
	h.auditRefreshFailure(ctx, event)
	respondRefreshUnauthorized(ctx, logID, publicError)
}

func respondRefreshUnauthorized(ctx *gin.Context, logID uuid.UUID, publicError string) {
	res := gokit.ErrorResponse(http.StatusUnauthorized, gokit.MsgSomethingWrong, logID, publicError)
	ctx.JSON(http.StatusUnauthorized, res)
}
