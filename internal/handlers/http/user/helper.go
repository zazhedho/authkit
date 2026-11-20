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

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
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

func (h *Handler) rejectBlockedLogin(ctx *gin.Context, logID uuid.UUID, logPrefix string, limiter LoginLimiter, loginIdentifier, normalizedIdentifier string) bool {
	if limiter == nil {
		return false
	}
	blocked, ttl, err := limiter.IsBlocked(ctx.Request.Context(), loginIdentifier)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; LoginLimiter.IsBlocked error: %v", logPrefix, err)
		if h.Settings.FailClosedLimiters {
			res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, "Login is temporarily unavailable.")
			ctx.JSON(http.StatusServiceUnavailable, res)
			return true
		}
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
	if !httpshared.IsNotFound(err) && !errors.Is(err, domainuser.ErrInvalidCredentials) {
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

	// Per client and identifier blocks only that client; per identifier backs off
	// instead of locking out, so a few requests cannot lock a victim out.
	var (
		blocked bool
		ttl     time.Duration
	)
	for _, c := range []struct {
		limiter LoginLimiter
		key     string
	}{{h.LoginLimiter, loginIdentifier}, {h.IdentifierLimiter, identifierKey(normalizedIdentifier)}} {
		if c.limiter == nil {
			continue
		}
		b, t, limiterErr := c.limiter.RegisterFailure(ctx.Request.Context(), c.key)
		if limiterErr != nil {
			logus.LogContextf(ctx, logus.LevelError, "%s; LoginLimiter.RegisterFailure error: %v", logPrefix, limiterErr)
			if h.Settings.FailClosedLimiters {
				res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, "Login is temporarily unavailable.")
				ctx.JSON(http.StatusServiceUnavailable, res)
				return
			}
		}
		if b && (!blocked || t > ttl) {
			blocked, ttl = true, t
		}
	}
	if blocked {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:   domainaudit.ActionLogin,
			Resource: "auth",
			Status:   domainaudit.StatusFailed,
			Message:  "Login delayed after repeated failures",
			AfterData: map[string]any{
				"identifier": normalizedIdentifier,
			},
		})
		logus.LogContextf(ctx, logus.LevelWarn, "%s; Login throttled after repeated failures", logPrefix)
		h.respondTooManyLoginAttempts(ctx, logID, ttl)
		return
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

// identifierKey is the limiter key that counts failures per account whatever
// the client.
func identifierKey(normalizedIdentifier string) string { return "identifier:" + normalizedIdentifier }

func (h *Handler) resetLoginLimiter(ctx *gin.Context, logPrefix string, limiter LoginLimiter, loginIdentifier string) {
	if limiter == nil {
		return
	}
	if err := limiter.Reset(ctx.Request.Context(), loginIdentifier); err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; LoginLimiter.Reset error: %v", logPrefix, err)
	}
}

// createLoginSession stores the login's session. A login whose session cannot
// be stored is an error: with sessions on, Auth would reject its tokens anyway.
func (h *Handler) createLoginSession(ctx *gin.Context, reqCtx context.Context, user *domainuser.Users, token, refreshToken, logPrefix string) error {
	if h.SessionSvc == nil {
		return nil
	}
	session, err := h.SessionSvc.CreateSession(reqCtx, user, token, refreshToken, domainsession.RequestMeta{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
	})
	if err != nil {
		return err
	}
	logus.LogContextf(ctx, logus.LevelInfo, "%s; Session created: %s", logPrefix, session.SessionID)
	return nil
}

// registrationOTPAcceptedMessage is the one answer the OTP-send route gives.
const registrationOTPAcceptedMessage = "If the address can register, a verification code has been sent."

// forgotPasswordMessage is the one answer the forgot-password route gives.
//
//nolint:gosec // a user-facing message, not a credential
const forgotPasswordMessage = "If the email is registered, password reset instructions have been sent."

func (h *Handler) forgotPasswordByEmail(ctx *gin.Context, req dtouser.ForgotPasswordRequest, logID uuid.UUID, logPrefix string) {
	normalizedEmail := domainuser.SanitizeEmail(req.Email)

	if h.ResetService != nil && normalizedEmail != "" {
		// Lookup, throttling and delivery all happen after the response, so
		// neither the status nor the latency depends on whether the email is
		// registered. Failures are only logged.
		appName := h.Settings.EmailAppName
		h.runAsync(ctx, logID, func(bg context.Context) {
			data, err := h.Service.GetUserByEmail(bg, normalizedEmail)
			if err != nil || data.ID == "" {
				return
			}
			if err := h.ResetService.RequestReset(bg, normalizedEmail, appName); err != nil {
				logus.LogContextf(bg, logus.LevelError, "%s; ResetService.RequestReset; ERROR: %s;", logPrefix, err)
			}
		})
	} else if h.ResetService == nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; %s", logPrefix, passwordResetEmailNotConfiguredMessage)
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusSuccess,
		Message: "Requested password reset email", AfterData: map[string]any{"email": normalizedEmail},
	})
	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, forgotPasswordMessage, logID, map[string]any{
		"cooldown": int(h.Settings.ResetCooldown.Seconds()),
	}))
}

// runAsync runs fn after the response. The work keeps the request and user ids
// for the logs; without a runner it runs inline.
func (h *Handler) runAsync(ctx *gin.Context, logID uuid.UUID, fn func(context.Context)) {
	reqCtx := logus.WithRequestID(ctx.Request.Context(), logID)
	if h.Async == nil {
		fn(reqCtx)
		return
	}
	h.Async.Go(reqCtx, fn)
}

func (h *Handler) resetPasswordByEmail(ctx *gin.Context, req dtouser.ResetPasswordRequest, logID uuid.UUID, logPrefix string) {
	if h.ResetService == nil {
		res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, passwordResetEmailNotConfiguredMessage)
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}
	reqCtx := ctx.Request.Context()
	// A weak password is refused before the token is consumed, so the user can
	// retry with the same link.
	if err := h.Service.ValidatePassword(req.NewPassword); err != nil {
		statusCode, res := userMutationErrorResponse(logID, err)
		ctx.JSON(statusCode, res)
		return
	}
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

	if err := h.Service.ResetPasswordByEmail(reqCtx, email, req.NewPassword); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionUpdate, Resource: "user_password_reset", Status: domainaudit.StatusFailed,
			Message: "Failed to reset password", ErrorMessage: err.Error(),
			AfterData: map[string]any{"email": email},
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.ResetPasswordByEmail; ERROR: %s;", logPrefix, err)
		// The password is unchanged unless only the session cleanup failed, so
		// give the token back and the user can retry with the same link.
		if !errors.Is(err, domainuser.ErrSessionRevocation) {
			if restoreErr := h.ResetService.RestoreReset(reqCtx, req.Token, email); restoreErr != nil {
				logus.LogContextf(ctx, logus.LevelError, "%s; ResetService.RestoreReset; ERROR: %s;", logPrefix, restoreErr)
			}
		}
		respondUserMutationError(ctx, logID, err)
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
		"expires_in":       int(h.Settings.AccessTTL.Seconds()),
		"expires_in_hours": int(h.Settings.AccessTTL.Hours()),
	}

	if refreshToken != "" {
		data["refresh_token"] = refreshToken
		data["refresh_expires_in_hours"] = int(h.Settings.RefreshTTL.Hours())
	}

	return data
}

func userMutationErrorResponse(logID uuid.UUID, err error) (int, *gokit.APIResponse) {
	switch {
	case httpshared.IsNotFound(err):
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, userNotFoundMessage)
	case errors.Is(err, domainuser.ErrDuplicate):
		return http.StatusConflict, gokit.ErrorResponse(http.StatusConflict, gokit.MsgExists, logID, "email or phone already exists")
	case errors.Is(err, domainuser.ErrRoleAboveActor), errors.Is(err, domainuser.ErrSelfRoleChange), errors.Is(err, domainuser.ErrAccessDenied):
		return http.StatusForbidden, gokit.Forbidden(logID, gokit.MsgAccessDenied)
	case errors.Is(err, domainuser.ErrLastSuperAdmin):
		return http.StatusConflict, gokit.ErrorResponse(http.StatusConflict, gokit.MsgSomethingWrong, logID, domainuser.ErrLastSuperAdmin.Error())
	case errors.Is(err, domainuser.ErrWeakPassword), errors.Is(err, domainuser.ErrPasswordTooLong),
		errors.Is(err, domainuser.ErrEmailRequired), errors.Is(err, domainuser.ErrPasswordRequired),
		errors.Is(err, domainuser.ErrPasswordIncorrect), errors.Is(err, domainuser.ErrReasonRequired),
		errors.Is(err, domainuser.ErrInvalidRole), errors.Is(err, domainuser.ErrSamePassword):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, err.Error())
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logID)
	}
}

func impersonationErrorResponse(logID uuid.UUID, err error) (int, *gokit.APIResponse) {
	switch {
	case httpshared.IsNotFound(err):
		return http.StatusNotFound, gokit.ErrorResponse(http.StatusNotFound, gokit.MsgNotFound, logID, userNotFoundMessage)
	case errors.Is(err, domainuser.ErrRoleAboveActor), errors.Is(err, domainuser.ErrSelfImpersonation):
		return http.StatusForbidden, gokit.Forbidden(logID, gokit.MsgAccessDenied)
	case errors.Is(err, domainuser.ErrImpersonatorRevoked):
		return http.StatusUnauthorized, gokit.Unauthorized(logID, "Your session is no longer valid. Please login again.")
	case errors.Is(err, domainuser.ErrReasonRequired), errors.Is(err, domainuser.ErrNestedImpersonation),
		errors.Is(err, domainuser.ErrTargetRequired), errors.Is(err, domainuser.ErrOriginalRequired),
		errors.Is(err, domainuser.ErrNotImpersonated):
		return http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, err.Error())
	default:
		return http.StatusInternalServerError, gokit.InternalServerError(logID)
	}
}

// issuedAfter is the cut-off new tokens for the user must be issued after.
func issuedAfter(u domainuser.Users) time.Time {
	if u.TokensValidAfter == nil {
		return time.Time{}
	}
	return *u.TokensValidAfter
}

// configEnabled reads a runtime flag. When the lookup fails it logs, writes the
// 500 response and returns ok=false.
func (h *Handler) configEnabled(ctx *gin.Context, logID uuid.UUID, logPrefix, key string, fallback bool) (enabled, ok bool) {
	enabled, err := h.isRuntimeConfigEnabled(ctx.Request.Context(), key, fallback)
	if errors.Is(err, domainappconfig.ErrInvalidValue) {
		// A malformed flag value must not take the auth routes down: use the
		// default and say so in the log.
		logus.LogContextf(ctx, logus.LevelWarn, "%s; Config %q holds an invalid value, using the default (%v): %v", logPrefix, key, fallback, err)
		return fallback, true
	}
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

// updateSnapshot is the audit view of an update request: the fields it may
// change, never the current password.
func updateSnapshot(req dtouser.Update) map[string]any {
	return map[string]any{"name": req.Name, "email": req.Email, "phone": req.Phone, "role": req.Role}
}

// userSnapshot is the audit view of a user: an allow-list of fields, so login
// bookkeeping, metadata and anything added to the entity later stay out of the
// audit trail.
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
			BeforeData:   userSnapshot(before),
			AfterData:    updateSnapshot(req),
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
		BeforeData: userSnapshot(before),
		AfterData:  userSnapshot(data),
	})

	res := gokit.Response(http.StatusOK, "User updated successfully", logID, dtouser.NewResponse(data, false))
	ctx.JSON(http.StatusOK, res)
}

// deleteUser deletes a user and audits the removal. The caller has already
// resolved the target id.
func (h *Handler) deleteUser(ctx *gin.Context, logID uuid.UUID, logPrefix, id, failedMessage, successMessage string) {
	reqCtx := ctx.Request.Context()
	before, _ := h.Service.GetUserByID(reqCtx, id)

	if err := h.Service.Delete(reqCtx, httpshared.ActorFrom(reqCtx), id); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "user",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      failedMessage,
			ErrorMessage: err.Error(),
			BeforeData:   userSnapshot(before),
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.Delete; ERROR: %s;", logPrefix, err)
		respondUserMutationError(ctx, logID, err)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   "user",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    successMessage,
		BeforeData: userSnapshot(before),
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

// sessionExpiry is when a rotated session expires: a full refresh TTL from now,
// but never past the absolute cap counted from the original login. The bool is
// false when the cap has already passed.
func (h *Handler) sessionExpiry(loginAt time.Time) (time.Time, bool) {
	expiry := time.Now().Add(h.Settings.RefreshTTL)
	if h.Settings.SessionMaxLifetime > 0 && !loginAt.IsZero() {
		limit := loginAt.Add(h.Settings.SessionMaxLifetime)
		if !limit.After(time.Now()) {
			return time.Time{}, false
		}
		if limit.Before(expiry) {
			expiry = limit
		}
	}
	return expiry, true
}

// revokeRefreshToken blacklists a refresh token the caller owns. A token that
// is invalid, belongs to someone else or is already revoked is ignored: the
// logout itself must still succeed.
func (h *Handler) revokeRefreshToken(ctx context.Context, userID, refreshToken string) error {
	claims, err := h.Tokens.Claims(refreshToken)
	if err != nil {
		//nolint:nilerr // a bad token is ignored on purpose: logout must still succeed
		return nil
	}
	if !strings.EqualFold(gokit.InterfaceString(claims["token_type"]), "refresh") ||
		gokit.InterfaceString(claims["user_id"]) != userID {
		return nil
	}
	if err := h.Service.LogoutUser(ctx, refreshToken); err != nil && !errors.Is(err, domainauth.ErrDuplicate) {
		return err
	}
	return nil
}

// denyWhileImpersonating answers 403 and audits the denial when the request
// carries an impersonation token; sensitive self-service routes are closed to
// it so an admin cannot change a user's own credentials through it.
func (h *Handler) denyWhileImpersonating(ctx *gin.Context, logID uuid.UUID, scope domainauth.Scope, resource, what string) bool {
	if !scope.IsImpersonated {
		return false
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:       domainaudit.ActionUpdate,
		Resource:     resource,
		ResourceID:   scope.UserID,
		Status:       domainaudit.StatusFailed,
		Message:      "Denied: cannot " + what + " while impersonating",
		ErrorMessage: "forbidden while impersonating",
	})
	ctx.JSON(http.StatusForbidden, gokit.Forbidden(logID, "This action is not available while impersonating a user."))
	return true
}

// registerLimiterFailure records a failed attempt on key and reports whether
// the key is now blocked. With FailClosedLimiters a limiter error answers 503
// itself and the second result is true.
func (h *Handler) registerLimiterFailure(ctx *gin.Context, logID uuid.UUID, logPrefix, key string) (blocked, responded bool) {
	if h.LoginLimiter == nil {
		return false, false
	}
	blocked, _, err := h.LoginLimiter.RegisterFailure(ctx.Request.Context(), key)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; LoginLimiter.RegisterFailure error: %v", logPrefix, err)
		if h.Settings.FailClosedLimiters {
			res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, "Service is temporarily unavailable.")
			ctx.JSON(http.StatusServiceUnavailable, res)
			return false, true
		}
	}
	return blocked, false
}

// confirmOwnPassword reads current_password from the body and checks it. When
// it cannot, the response is already written and ok is false.
func (h *Handler) confirmOwnPassword(ctx *gin.Context, logID uuid.UUID, logPrefix, userID string) bool {
	var req dtouser.DeleteOwn
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return false
	}
	if err := h.Service.VerifyPassword(ctx.Request.Context(), userID, req.CurrentPassword); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     "user",
			ResourceID:   userID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to delete own user: current password check failed",
			ErrorMessage: err.Error(),
		})
		respondUserMutationError(ctx, logID, err)
		return false
	}
	return true
}

// reissueSession binds the new token pair to the caller's session after a
// password change and ends every other session. A caller whose token has no
// session (or whose session passed its lifetime cap) gets a fresh one.
func (h *Handler) reissueSession(ctx *gin.Context, reqCtx context.Context, user *domainuser.Users, accessToken, refreshToken, logPrefix string) error {
	if h.SessionSvc == nil {
		return nil
	}
	current := h.currentSession(reqCtx, ctx)
	if current != nil {
		if expiry, withinCap := h.sessionExpiry(current.LoginAt); withinCap {
			if err := h.SessionSvc.DestroyOtherSessions(reqCtx, user.ID, current.SessionID); err != nil {
				return err
			}
			return h.SessionSvc.RotateSessionTokens(reqCtx, current.SessionID, accessToken, refreshToken, expiry)
		}
	}
	if err := h.SessionSvc.DestroyAllUserSessions(reqCtx, user.ID); err != nil {
		return err
	}
	return h.createLoginSession(ctx, reqCtx, user, accessToken, refreshToken, logPrefix)
}

// currentSession is the session of the request's access token, or nil.
func (h *Handler) currentSession(reqCtx context.Context, ctx *gin.Context) *domainsession.Session {
	token, _ := ctx.Get("token")
	tokenString, _ := token.(string)
	session, err := h.SessionSvc.GetSessionByToken(reqCtx, tokenString)
	if err != nil {
		return nil
	}
	return session
}
