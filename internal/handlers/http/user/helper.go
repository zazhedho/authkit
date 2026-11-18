package user

import (
	"context"
	"errors"
	"fmt"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	"github.com/zazhedho/authkit/internal/infrastructure/token"
	servicereset "github.com/zazhedho/authkit/internal/services/reset"
	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	publicRegistrationDisabledMessage      = "Public registration is currently disabled."
	registrationOTPNotConfiguredMessage    = "registration OTP service is not configured"
	passwordResetEmailNotConfiguredMessage = "password reset email service is not configured"
	failedRenewLoginSessionMessage         = "Failed to renew login session"
	userNotFoundMessage                    = "user not found"
)

func (h *HandlerUser) respondTooManyLoginAttempts(ctx *gin.Context, logId uuid.UUID, ttl time.Duration) {
	if ttl > 0 {
		ctx.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))
	}

	message := "Too many login attempts. Please try again later."
	if ttl > 0 {
		message = fmt.Sprintf("Too many login attempts. Try again in %d seconds.", int(ttl.Seconds()))
	}

	res := gokit.Response(http.StatusTooManyRequests, gokit.MsgSomethingWrong, logId, nil)
	res.Error = gokit.Errors{Code: http.StatusTooManyRequests, Message: message}
	ctx.AbortWithStatusJSON(http.StatusTooManyRequests, res)
}

func (h *HandlerUser) respondThrottle(ctx *gin.Context, logId uuid.UUID, ttl time.Duration, message string) {
	if ttl > 0 {
		ctx.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))
	}

	if message == "" {
		message = "Too many requests. Please try again later."
	}

	res := gokit.Response(http.StatusTooManyRequests, gokit.MsgSomethingWrong, logId, nil)
	res.Error = gokit.Errors{Code: http.StatusTooManyRequests, Message: message}
	ctx.AbortWithStatusJSON(http.StatusTooManyRequests, res)
}

func (h *HandlerUser) registrationConflict(ctx context.Context, email, phone string) (string, string, error) {
	user, err := h.Service.GetUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", "Service.GetUserByEmail", err
	}
	if user.Id != "" {
		return "email already exists", "", nil
	}
	if phone == "" {
		return "", "", nil
	}

	user, err = h.Service.GetUserByPhone(ctx, gokit.NormalizePhoneTo62(phone))
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", "Service.GetUserByPhone", err
	}
	if user.Id != "" {
		return "phone number already exists", "", nil
	}
	return "", "", nil
}

func (h *HandlerUser) rejectBlockedLogin(ctx *gin.Context, logId uuid.UUID, logPrefix, loginIdentifier, normalizedIdentifier string) bool {
	if h.LoginLimiter == nil {
		return false
	}
	blocked, ttl, err := h.LoginLimiter.IsBlocked(ctx.Request.Context(), loginIdentifier)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; LoginLimiter.IsBlocked error: %v", logPrefix, err))
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
	logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("%s; Too many attempts", logPrefix))
	h.respondTooManyLoginAttempts(ctx, logId, ttl)
	return true
}

func (h *HandlerUser) handleLoginFailure(ctx *gin.Context, logId uuid.UUID, logPrefix, normalizedIdentifier, loginIdentifier string, err error) {
	logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.LoginUser; ERROR: %s;", logPrefix, err))
	if !errors.Is(err, gorm.ErrRecordNotFound) && err.Error() != ErrHashPassword {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogin,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Login failed due to internal error",
			ErrorMessage: err.Error(),
			AfterData:    map[string]any{"identifier": normalizedIdentifier},
		})
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logId))
		return
	}

	if h.LoginLimiter != nil {
		blocked, ttl, limiterErr := h.LoginLimiter.RegisterFailure(ctx.Request.Context(), loginIdentifier)
		if limiterErr != nil {
			logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; LoginLimiter.RegisterFailure error: %v", logPrefix, limiterErr))
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
			logus.WriteLogWithContext(ctx, logus.LogLevelWarn, fmt.Sprintf("%s; Account temporarily locked after repeated failures", logPrefix))
			h.respondTooManyLoginAttempts(ctx, logId, ttl)
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
	res := gokit.Response(http.StatusBadRequest, InvalidCred, logId, nil)
	res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: MsgCredential}
	ctx.JSON(http.StatusBadRequest, res)
}

func (h *HandlerUser) resetLoginLimiter(ctx *gin.Context, logPrefix, loginIdentifier string) {
	if h.LoginLimiter == nil {
		return
	}
	if err := h.LoginLimiter.Reset(ctx.Request.Context(), loginIdentifier); err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; LoginLimiter.Reset error: %v", logPrefix, err))
	}
}

func (h *HandlerUser) createLoginSession(ctx *gin.Context, reqCtx context.Context, user *domainuser.Users, userErr error, token, refreshToken, logPrefix string) {
	if h.SessionSvc == nil || userErr != nil || refreshToken == "" {
		return
	}
	session, err := h.SessionSvc.CreateSession(reqCtx, user, token, refreshToken, domainsession.RequestMeta{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
	})
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Failed to create session: %v", logPrefix, err))
		return
	}
	logus.WriteLogWithContext(ctx, logus.LogLevelInfo, fmt.Sprintf("%s; Session created: %s", logPrefix, session.SessionID))
}

func (h *HandlerUser) forgotPasswordByEmail(ctx *gin.Context, req dtouser.ForgotPasswordRequest, logId uuid.UUID, logPrefix string) {
	if h.ResetService == nil {
		res := gokit.Response(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusServiceUnavailable, Message: passwordResetEmailNotConfiguredMessage}
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}

	reqCtx := ctx.Request.Context()
	normalizedEmail := gokit.SanitizeEmail(req.Email)
	if data, err := h.Service.GetUserByEmail(reqCtx, normalizedEmail); err == nil && data.Id != "" {
		appName := h.Settings.EmailAppName
		if err := h.ResetService.RequestReset(reqCtx, normalizedEmail, appName); err != nil {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
				Message: "Failed to request password reset email", ErrorMessage: err.Error(),
				AfterData: map[string]any{"email": normalizedEmail},
			})
			if throttle, ok := errors.AsType[*servicereset.ThrottleError](err); ok {
				h.respondThrottle(ctx, logId, throttle.RetryAfter, "Password reset request is throttled. Please try again later.")
				return
			}
			statusCode := http.StatusInternalServerError
			message := "Failed to send password reset email. Please contact support with the log ID."
			if errors.Is(err, servicereset.ErrResetNotConfigured) || errors.Is(err, servicereset.ErrResetDeliveryFailed) {
				statusCode = http.StatusServiceUnavailable
				message = "Password reset email service is temporarily unavailable."
			}
			res := gokit.Response(statusCode, gokit.MsgSomethingWrong, logId, nil)
			res.Error = gokit.Errors{Code: statusCode, Message: message}
			ctx.JSON(statusCode, res)
			return
		}
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusSuccess,
		Message: "Requested password reset email", AfterData: map[string]any{"email": normalizedEmail},
	})
	res := gokit.Response(http.StatusOK, "Password reset instructions sent to your email", logId, map[string]any{
		"cooldown": int(h.Settings.ResetCooldown.Seconds()),
	})
	logus.WriteLogWithContext(ctx, logus.LogLevelInfo, fmt.Sprintf("%s; Password reset instructions sent to email: %s", logPrefix, normalizedEmail))
	ctx.JSON(http.StatusOK, res)
}

func (h *HandlerUser) resetPasswordByEmail(ctx *gin.Context, req dtouser.ResetPasswordRequest, logId uuid.UUID, logPrefix string) {
	if h.ResetService == nil {
		res := gokit.Response(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusServiceUnavailable, Message: passwordResetEmailNotConfiguredMessage}
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
		if errors.Is(err, servicereset.ErrResetNotConfigured) {
			statusCode = http.StatusServiceUnavailable
			message = passwordResetEmailNotConfiguredMessage
		}
		res := gokit.Response(statusCode, gokit.MsgSomethingWrong, logId, nil)
		res.Error = gokit.Errors{Code: statusCode, Message: message}
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
			statusCode, res := userMutationErrorResponse(logId, err)
			ctx.JSON(statusCode, res)
			return
		}
		userID = user.Id
	}
	if err := h.Service.ResetPasswordByEmail(reqCtx, email, req.NewPassword); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to reset password", ErrorMessage: err.Error(),
			AfterData: map[string]any{"email": email},
		})
		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	if err := h.revokePasswordResetSessions(reqCtx, userID); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to revoke sessions after password reset", ErrorMessage: err.Error(),
			AfterData: map[string]any{"email": email},
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; SessionSvc.DestroyAllUserSessions; ERROR: %s;", logPrefix, err))
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logId))
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusSuccess,
		Message: "Reset password success", AfterData: map[string]any{"email": email},
	})
	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, "Password reset successfully", logId, nil))
}

func (h *HandlerUser) isRuntimeConfigEnabled(ctx context.Context, configKey string, fallback bool) (bool, error) {
	if h.AppConfigService == nil {
		return fallback, nil
	}
	return h.AppConfigService.IsEnabled(ctx, configKey, fallback)
}

func (h *HandlerUser) buildAuthTokenResponse(accessToken, refreshToken string) map[string]any {
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

func userMutationErrorResponse(logId uuid.UUID, err error) (int, *gokit.ApiResponse) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logId, userNotFoundMessage)
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logId, "email or phone already exists")
	}

	errMsg := err.Error()
	switch {
	case errMsg == userNotFoundMessage:
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logId, userNotFoundMessage)
	case errMsg == "invalid or expired token":
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logId, "invalid or expired reset token")
	case strings.HasPrefix(errMsg, "access denied:"),
		strings.Contains(errMsg, "superadmin"):
		return http.StatusForbidden, gokit.Forbidden(logId, gokit.MsgAccessDenied)
	case strings.Contains(errMsg, "already exists"):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logId, errMsg)
	case strings.HasPrefix(errMsg, "invalid role:"),
		strings.HasPrefix(errMsg, "password must "),
		strings.HasPrefix(errMsg, "new password must "):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logId, errMsg)
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logId)
	}
}

func impersonationErrorResponse(logId uuid.UUID, err error) (int, *gokit.ApiResponse) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logId, userNotFoundMessage)
	}

	errMsg := err.Error()
	switch {
	case strings.HasPrefix(errMsg, "cannot impersonate"):
		return http.StatusForbidden, gokit.Forbidden(logId, gokit.MsgAccessDenied)
	case strings.HasPrefix(errMsg, "cannot start"),
		strings.HasPrefix(errMsg, "target user id"),
		strings.HasPrefix(errMsg, "original user id"),
		strings.HasPrefix(errMsg, "current session"):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logId, errMsg)
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logId)
	}
}

func buildImpersonationClaimsOverrideFromClaims(claims map[string]any) *token.AppClaims {
	if claims == nil || !gokit.InterfaceBool(claims["is_impersonated"]) {
		return nil
	}

	return &token.AppClaims{
		IsImpersonated:   true,
		OriginalUserId:   gokit.InterfaceString(claims["original_user_id"]),
		OriginalUsername: gokit.InterfaceString(claims["original_username"]),
		OriginalRole:     gokit.InterfaceString(claims["original_role"]),
	}
}
