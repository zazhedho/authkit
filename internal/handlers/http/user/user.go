package user

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainotp "github.com/zazhedho/authkit/internal/domain/otp"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	httpshared "github.com/zazhedho/authkit/internal/handlers/http/shared"

	"github.com/gin-gonic/gin"
)

// FlagKeys are the runtime app-config keys the handler consults.
type FlagKeys struct {
	PublicRegistration string
	RegisterOTP        string
	PasswordResetEmail string
}

// Settings carries the values the handler needs at request time.
type Settings struct {
	AppEnv, EmailAppName string
	// DevEnv enables the development password-reset fallback.
	DevEnv                bool
	AccessTTL, RefreshTTL time.Duration
	OTPCooldown           time.Duration
	// ResetCooldown is the resend cooldown reported by the forgot-password
	// email flow.
	ResetCooldown time.Duration
	Flags         FlagKeys
}

type Handler struct {
	Service      Service
	SessionSvc   SessionService
	LoginLimiter LoginLimiter
	httpshared.AuditWriter
	AppConfigService AppConfigService
	OTPService       OTPService
	ResetService     ResetService
	Tokens           TokenIssuer
	Settings         Settings
}

type Options struct {
	AppConfigService AppConfigService
	OTPService       OTPService
	ResetService     ResetService
	Tokens           TokenIssuer
	Settings         Settings
}

func New(
	s Service,
	sessionSvc SessionService,
	limiter LoginLimiter,
	auditService httpshared.AuditService,
	options Options,
) *Handler {
	return &Handler{
		Service:          s,
		SessionSvc:       sessionSvc,
		LoginLimiter:     limiter,
		AuditWriter:      httpshared.NewAuditWriter(auditService, "UserHandler"),
		AppConfigService: options.AppConfigService,
		OTPService:       options.OTPService,
		ResetService:     options.ResetService,
		Tokens:           options.Tokens,
		Settings:         options.Settings,
	}
}

func (h *Handler) Register(ctx *gin.Context) {
	var req dtouser.UserRegister
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][Register]"
	reqCtx := ctx.Request.Context()

	if !h.registrationOpen(ctx, logId, logPrefix) {
		return
	}
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, gokit.JsonEncode(gokit.RedactSensitivePayload(req))))

	otpEnabled, ok := h.configEnabled(ctx, logId, logPrefix, h.Settings.Flags.RegisterOTP, false)
	if !ok {
		return
	}
	if otpEnabled {
		if strings.TrimSpace(req.OTPCode) == "" {
			res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
			res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "otp_code is required"}
			ctx.JSON(http.StatusBadRequest, res)
			return
		}
		if h.OTPService == nil {
			res := gokit.Response(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logId, nil)
			res.Error = gokit.Errors{Code: http.StatusServiceUnavailable, Message: registrationOTPNotConfiguredMessage}
			ctx.JSON(http.StatusServiceUnavailable, res)
			return
		}
		if err := h.OTPService.VerifyRegisterOTP(ctx.Request.Context(), req.Email, req.OTPCode); err != nil {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action:       domainaudit.ActionCreate,
				Resource:     "user",
				Status:       domainaudit.StatusFailed,
				Message:      "Failed to verify registration OTP",
				ErrorMessage: err.Error(),
				AfterData: map[string]any{
					"email": req.Email,
				},
			})
			statusCode := http.StatusBadRequest
			message := "invalid or expired OTP"
			if errors.Is(err, domainotp.ErrTooManyAttempt) {
				message = "too many OTP attempts"
			}
			if errors.Is(err, domainotp.ErrNotConfigured) {
				statusCode = http.StatusServiceUnavailable
				message = registrationOTPNotConfiguredMessage
			}
			res := gokit.Response(statusCode, gokit.MsgSomethingWrong, logId, nil)
			res.Error = gokit.Errors{Code: statusCode, Message: message}
			ctx.JSON(statusCode, res)
			return
		}
		req.EmailVerified = true
	}

	data, err := h.Service.RegisterUser(reqCtx, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "user",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to register user",
			ErrorMessage: err.Error(),
			AfterData: map[string]any{
				"name":  req.Name,
				"email": req.Email,
				"phone": req.Phone,
			},
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.RegisterUser; Error: %+v", logPrefix, err))
		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: data.Id,
		ActorRole:   data.Role,
		Action:      domainaudit.ActionCreate,
		Resource:    "user",
		ResourceID:  data.Id,
		Status:      domainaudit.StatusSuccess,
		Message:     "Registered user",
		AfterData:   userSnapshot(data),
	})

	res := gokit.Response(http.StatusCreated, "User registered successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusCreated, res)
}

func (h *Handler) GetRegisterStatus(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GetRegisterStatus]"

	registerEnabled, ok := h.configEnabled(ctx, logId, logPrefix, h.Settings.Flags.PublicRegistration, true)
	if !ok {
		return
	}
	otpEnabled, ok := h.configEnabled(ctx, logId, logPrefix, h.Settings.Flags.RegisterOTP, false)
	if !ok {
		return
	}

	res := gokit.Response(http.StatusOK, "Get register status successfully", logId, map[string]any{
		"enabled":      registerEnabled,
		"otp_enabled":  otpEnabled,
		"otp_cooldown": int(h.Settings.OTPCooldown.Seconds()),
	})
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) SendRegisterOTP(ctx *gin.Context) {
	var req dtouser.SendRegisterOTPRequest
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][SendRegisterOTP]"
	reqCtx := ctx.Request.Context()

	if !h.registrationOpen(ctx, logId, logPrefix) {
		return
	}
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	otpEnabled, ok := h.configEnabled(ctx, logId, logPrefix, h.Settings.Flags.RegisterOTP, false)
	if !ok {
		return
	}
	if !otpEnabled {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgSomethingWrong, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "registration OTP is disabled"}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	if h.OTPService == nil {
		res := gokit.Response(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusServiceUnavailable, Message: registrationOTPNotConfiguredMessage}
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}

	normalizedEmail := gokit.SanitizeEmail(req.Email)
	conflict, lookup, err := h.registrationConflict(reqCtx, normalizedEmail, req.Phone)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; %s; Error: %+v", logPrefix, lookup, err))
		httpshared.RespondInternalError(ctx, logId)
		return
	}
	if conflict != "" {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgExists, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: conflict}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	if err := h.OTPService.SendRegisterOTP(ctx.Request.Context(), normalizedEmail, h.Settings.EmailAppName); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "user_registration_otp",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to send registration OTP",
			ErrorMessage: err.Error(),
			AfterData: map[string]any{
				"email": normalizedEmail,
			},
		})
		if throttle, ok := errors.AsType[*domainotp.ThrottleError](err); ok {
			h.respondThrottle(ctx, logId, throttle.RetryAfter, "OTP request is throttled. Please try again later.")
			return
		}
		if errors.Is(err, domainotp.ErrNotConfigured) || errors.Is(err, domainotp.ErrDeliveryFailed) {
			statusCode := http.StatusServiceUnavailable
			res := gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logId, "Registration OTP service is temporarily unavailable.")
			ctx.JSON(statusCode, res)
			return
		}

		httpshared.RespondInternalError(ctx, logId)
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionCreate,
		Resource: "user_registration_otp",
		Status:   domainaudit.StatusSuccess,
		Message:  "Sent registration OTP",
		AfterData: map[string]any{
			"email": normalizedEmail,
		},
	})
	res := gokit.Response(http.StatusOK, "Registration OTP sent successfully", logId, nil)
	logus.WriteLogWithContext(ctx, logus.LogLevelInfo, fmt.Sprintf("%s; Registration OTP sent successfully", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) AdminCreateUser(ctx *gin.Context) {
	var req dtouser.AdminCreateUser
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][AdminCreateUser]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, gokit.JsonEncode(gokit.RedactSensitivePayload(req))))

	data, err := h.Service.AdminCreateUser(reqCtx, httpshared.ActorFrom(reqCtx), req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     "user",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to create user",
			ErrorMessage: err.Error(),
			AfterData: map[string]any{
				"name":  req.Name,
				"email": req.Email,
				"phone": req.Phone,
				"role":  req.Role,
			},
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.AdminCreateUser; Error: %+v", logPrefix, err))
		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionCreate,
		Resource:   "user",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Created user by admin",
		AfterData:  userSnapshot(data),
	})

	res := gokit.Response(http.StatusCreated, "User created successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusCreated, res)
}

func (h *Handler) Login(ctx *gin.Context) {
	var req dtouser.Login
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserController][Login]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, gokit.JsonEncode(gokit.RedactSensitivePayload(req))))

	normalizedIdentifier, err := domainuser.ResolveLoginIdentifier(req.Identifier, req.Email)
	if err != nil {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgInvalidRequest, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: err.Error()}
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	loginIdentifier := fmt.Sprintf("%s:%s", ctx.ClientIP(), normalizedIdentifier)
	if h.rejectBlockedLogin(ctx, logId, logPrefix, loginIdentifier, normalizedIdentifier) {
		return
	}

	token, err := h.Service.LoginUser(reqCtx, req, logId.String(), dtouser.LoginMetadata{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	})
	if err != nil {
		h.handleLoginFailure(ctx, logId, logPrefix, normalizedIdentifier, loginIdentifier, err)
		return
	}

	var (
		loggedInUser domainuser.Users
		userErr      error
	)
	if strings.Contains(normalizedIdentifier, "@") {
		loggedInUser, userErr = h.Service.GetUserByEmail(reqCtx, normalizedIdentifier)
	} else {
		loggedInUser, userErr = h.Service.GetUserByPhone(reqCtx, normalizedIdentifier)
	}
	loginUserID := ""
	if userErr == nil {
		loginUserID = loggedInUser.Id
	}

	refreshToken := ""
	if userErr == nil {
		refreshToken, err = h.Tokens.GenerateRefresh(loggedInUser.Id, loggedInUser.Name, loggedInUser.Role, logId.String())
		if err != nil {
			respondStepFailed(ctx, logId, logPrefix, "GenerateRefreshJwt", err)
			return
		}
	}

	h.resetLoginLimiter(ctx, logPrefix, loginIdentifier)
	h.createLoginSession(ctx, reqCtx, &loggedInUser, userErr, token, refreshToken, logPrefix)

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: loginUserID,
		ActorRole:   loggedInUser.Role,
		Action:      domainaudit.ActionLogin,
		Resource:    "auth",
		ResourceID:  loginUserID,
		Status:      domainaudit.StatusSuccess,
		Message:     "Login success",
		AfterData: map[string]any{
			"identifier": normalizedIdentifier,
		},
	})

	data := h.buildAuthTokenResponse(token, refreshToken)
	res := gokit.Response(http.StatusOK, "success", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(gokit.RedactSensitivePayload(data))))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GoogleLogin(ctx *gin.Context) {
	var req dtouser.GoogleLogin
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GoogleLogin]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	registerEnabled, ok := h.configEnabled(ctx, logId, logPrefix, h.Settings.Flags.PublicRegistration, true)
	if !ok {
		return
	}

	user, isNewUser, err := h.Service.LoginWithGoogle(reqCtx, req, dtouser.LoginMetadata{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	}, registerEnabled)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogin,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Google login failed",
			ErrorMessage: err.Error(),
			AfterData: map[string]any{
				"provider": "google",
			},
		})

		statusCode := http.StatusBadRequest
		switch {
		case errors.Is(err, domainuser.ErrGoogleNotConfigured):
			statusCode = http.StatusServiceUnavailable
		case errors.Is(err, domainuser.ErrGoogleTokenInvalid), errors.Is(err, domainuser.ErrGoogleEmailMissing):
			statusCode = http.StatusUnauthorized
		case errors.Is(err, domainuser.ErrPublicRegistrationDisabled):
			statusCode = http.StatusForbidden
		}

		res := gokit.InternalServerError(logId)
		switch {
		case errors.Is(err, domainuser.ErrGoogleNotConfigured):
			res = gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logId, "Google login is not configured.")
		case errors.Is(err, domainuser.ErrGoogleTokenInvalid):
			res = gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logId, "Invalid Google token.")
		case errors.Is(err, domainuser.ErrGoogleEmailMissing):
			res = gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logId, "Google account email is not available.")
		case errors.Is(err, domainuser.ErrPublicRegistrationDisabled):
			res = gokit.Forbidden(logId, publicRegistrationDisabledMessage)
		}
		ctx.JSON(statusCode, res)
		return
	}

	accessToken, err := h.Tokens.Generate(user.Id, user.Name, user.Role, logId.String())
	if err != nil {
		respondStepFailed(ctx, logId, logPrefix, "GenerateJwt", err)
		return
	}

	refreshToken, err := h.Tokens.GenerateRefresh(user.Id, user.Name, user.Role, logId.String())
	if err != nil {
		respondStepFailed(ctx, logId, logPrefix, "GenerateRefreshJwt", err)
		return
	}

	if h.SessionSvc != nil {
		session, errSession := h.SessionSvc.CreateSession(reqCtx, &user, accessToken, refreshToken, domainsession.RequestMeta{
			IP:        ctx.ClientIP(),
			UserAgent: ctx.GetHeader("User-Agent"),
		})
		if errSession != nil {
			logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Failed to create session: %v", logPrefix, errSession))
		} else {
			logus.WriteLogWithContext(ctx, logus.LogLevelInfo, fmt.Sprintf("%s; Session created: %s", logPrefix, session.SessionID))
		}
	}

	successMessage := "Google login success"
	if isNewUser {
		successMessage = "Google registration success"
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: user.Id,
		ActorRole:   user.Role,
		Action:      domainaudit.ActionLogin,
		Resource:    "auth",
		ResourceID:  user.Id,
		Status:      domainaudit.StatusSuccess,
		Message:     successMessage,
		AfterData: map[string]any{
			"provider":    "google",
			"email":       user.Email,
			"is_new_user": isNewUser,
		},
	})

	data := h.buildAuthTokenResponse(accessToken, refreshToken)
	data["is_new_user"] = isNewUser
	data["provider"] = "google"

	res := gokit.Response(http.StatusOK, successMessage, logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelInfo, fmt.Sprintf("%s; %s; Data: %+v", logPrefix, successMessage, gokit.JsonEncode(gokit.RedactSensitivePayload(data))))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) RefreshToken(ctx *gin.Context) {
	var req dtouser.RefreshTokenRequest
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][RefreshToken]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	tokenClaims, err := h.Tokens.Claims(req.RefreshToken)
	if err != nil {
		h.rejectRefresh(ctx, logId, "invalid or expired refresh token", domainaudit.AuditEvent{
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token is invalid or expired",
		})
		return
	}

	claimUserID := gokit.InterfaceString(tokenClaims["user_id"])
	claimRole := gokit.InterfaceString(tokenClaims["role"])
	if !strings.EqualFold(gokit.InterfaceString(tokenClaims["token_type"]), "refresh") {
		h.rejectRefresh(ctx, logId, "invalid token type", domainaudit.AuditEvent{
			ActorUserID:  claimUserID,
			ActorRole:    claimRole,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The provided token is not a refresh token",
		})
		return
	}

	isBlacklisted, err := h.Service.IsTokenRevoked(ctx.Request.Context(), req.RefreshToken)
	if err != nil {
		h.failRefresh(ctx, logId, logPrefix, "BlacklistRepo.ExistsByToken", err, domainaudit.AuditEvent{
			ActorUserID: claimUserID,
			ActorRole:   claimRole,
			Message:     "Failed to validate login session renewal",
		})
		return
	}
	if isBlacklisted {
		h.rejectRefresh(ctx, logId, "refresh token has been revoked", domainaudit.AuditEvent{
			ActorUserID:  claimUserID,
			ActorRole:    claimRole,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token has already been revoked",
		})
		return
	}

	userID := claimUserID
	user, err := h.Service.GetUserById(reqCtx, userID)
	if err != nil {
		h.auditRefreshFailure(ctx, domainaudit.AuditEvent{
			ActorUserID:  userID,
			ActorRole:    claimRole,
			ResourceID:   userID,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The token owner user account was not found",
		})
		statusCode := http.StatusInternalServerError
		if httpshared.IsNotFound(err) {
			statusCode = http.StatusNotFound
		}
		res := gokit.Response(statusCode, gokit.MsgSomethingWrong, logId, nil)
		res.Error = userNotFoundMessage
		ctx.JSON(statusCode, res)
		return
	}

	imp := impersonationFromClaims(tokenClaims)
	accessToken, err := h.issueAccessToken(&user, logId.String(), imp)
	if err != nil {
		h.failRefresh(ctx, logId, logPrefix, "GenerateJwtWithClaims", err, domainaudit.AuditEvent{
			ActorUserID: userID,
			ActorRole:   user.Role,
			ResourceID:  userID,
			Message:     "Failed to issue a new access token",
		})
		return
	}

	refreshToken, err := h.issueRefreshToken(&user, logId.String(), imp)
	if err != nil {
		h.failRefresh(ctx, logId, logPrefix, "GenerateRefreshJwt", err, domainaudit.AuditEvent{
			ActorUserID: userID,
			ActorRole:   user.Role,
			ResourceID:  userID,
			Message:     "Failed to issue a new refresh token",
		})
		return
	}

	if h.SessionSvc != nil {
		session, sessionErr := h.SessionSvc.GetSessionByRefreshToken(reqCtx, req.RefreshToken)
		if sessionErr != nil {
			h.auditRefreshFailure(ctx, domainaudit.AuditEvent{
				ActorUserID:  userID,
				ActorRole:    user.Role,
				ResourceID:   userID,
				Message:      failedRenewLoginSessionMessage,
				ErrorMessage: "No active session was found for the refresh token",
			})
			logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; SessionSvc.GetSessionByRefreshToken; ERROR: %s;", logPrefix, sessionErr))
			respondRefreshUnauthorized(ctx, logId, "session not found for refresh token")
			return
		}

		refreshExpAt := time.Now().Add(h.Settings.RefreshTTL)
		if sessionErr = h.SessionSvc.RotateSessionTokens(reqCtx, session.SessionID, accessToken, refreshToken, refreshExpAt); sessionErr != nil {
			h.failRefresh(ctx, logId, logPrefix, "SessionSvc.RotateSessionTokens", sessionErr, domainaudit.AuditEvent{
				ActorUserID: userID,
				ActorRole:   user.Role,
				ResourceID:  userID,
				Message:     "Failed to rotate login session tokens",
				Metadata: map[string]any{
					"session_id": session.SessionID,
				},
			})
			return
		}
	}

	if err = h.Service.LogoutUser(reqCtx, req.RefreshToken); err != nil {
		h.failRefresh(ctx, logId, logPrefix, "Service.LogoutUser(refresh)", err, domainaudit.AuditEvent{
			ActorUserID: userID,
			ActorRole:   user.Role,
			ResourceID:  userID,
			Message:     "Failed to revoke previous login session token",
		})
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: userID,
		ActorRole:   user.Role,
		Action:      domainaudit.ActionRefresh,
		Resource:    "auth_token",
		ResourceID:  userID,
		Status:      domainaudit.StatusSuccess,
		Message:     "Renewed login session",
	})

	res := gokit.Response(http.StatusOK, "Refresh token rotated successfully", logId, h.buildAuthTokenResponse(accessToken, refreshToken))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) Logout(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserController][Logout]"
	reqCtx := ctx.Request.Context()

	token, ok := ctx.Get("token")
	if !ok {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogout,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Logout failed because token missing in context",
			ErrorMessage: "token not found",
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; token not found in context", logPrefix))
		httpshared.RespondInternalError(ctx, logId)
		return
	}

	if h.SessionSvc != nil {
		errSession := h.SessionSvc.DestroySessionByToken(reqCtx, token.(string))
		if errSession != nil {
			logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Failed to destroy session: %v", logPrefix, errSession))
		} else {
			logus.WriteLogWithContext(ctx, logus.LogLevelInfo, fmt.Sprintf("%s; Session destroyed successfully", logPrefix))
		}
	}

	if err := h.Service.LogoutUser(reqCtx, token.(string)); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogout,
			Resource:     "auth",
			Status:       domainaudit.StatusFailed,
			Message:      "Logout failed",
			ErrorMessage: err.Error(),
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.LogoutUser; Error: %+v", logPrefix, err))
		httpshared.RespondInternalError(ctx, logId)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionLogout,
		Resource: "auth",
		Status:   domainaudit.StatusSuccess,
		Message:  "Logout success",
	})

	res := gokit.Response(http.StatusOK, "User logged out successfully", logId, nil)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Success: User logged out successfully", logPrefix))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetUserById(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GetUserByID]"
	reqCtx := ctx.Request.Context()

	id, err := gokit.ValidateUUIDParam(ctx, logId)
	if err != nil {
		return
	}

	data, err := h.Service.GetUserById(reqCtx, id)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetUserByID; ERROR: %s;", logPrefix, err))
		respondUserLookupError(ctx, logId, err)
		return
	}

	res := gokit.Response(http.StatusOK, "success", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetUserByAuth(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GetUserByAuth]"
	reqCtx := ctx.Request.Context()
	scope := domainauth.FromContext(reqCtx)

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logId)
		return
	}

	data, err := h.Service.GetUserByAuth(reqCtx, scope.UserID)
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.GetUserByAuth; ERROR: %s;", logPrefix, err))
		respondUserLookupError(ctx, logId, err)
		return
	}

	if scope.IsImpersonated {
		data["is_impersonated"] = true
		data["impersonator"] = map[string]any{
			"user_id":  scope.OriginalUserID,
			"username": scope.OriginalUsername,
			"role":     scope.OriginalRole,
		}
	} else {
		data["is_impersonated"] = false
	}

	res := gokit.Response(http.StatusOK, "success", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) ImpersonateUser(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][ImpersonateUser]"
	reqCtx := ctx.Request.Context()

	id, err := gokit.ValidateUUIDParam(ctx, logId)
	if err != nil {
		return
	}

	token, err := h.Service.ImpersonateUser(reqCtx, httpshared.ActorFrom(reqCtx), id, logId.String())
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogin,
			Resource:     "user_impersonation",
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to impersonate user",
			ErrorMessage: err.Error(),
			AfterData: map[string]any{
				"target_user_id": id,
			},
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.ImpersonateUser; ERROR: %s;", logPrefix, err))

		statusCode, res := impersonationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionLogin,
		Resource:   "user_impersonation",
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Started impersonation session",
		AfterData: map[string]any{
			"target_user_id": id,
		},
		Metadata: map[string]any{
			"impersonation_action": "start",
			"target_user_id":       id,
		},
	})

	res := gokit.Response(http.StatusOK, "Impersonation started successfully", logId, h.buildAuthTokenResponse(token, ""))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) StopImpersonation(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][StopImpersonation]"
	reqCtx := ctx.Request.Context()

	scope := domainauth.FromContext(reqCtx)
	originalUserID := scope.OriginalUserID
	if !scope.IsImpersonated || originalUserID == "" {
		res := gokit.Response(http.StatusBadRequest, gokit.MsgSomethingWrong, logId, nil)
		res.Error = "current session is not impersonated"
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	token, err := h.Service.StopImpersonation(reqCtx, httpshared.ActorFrom(reqCtx), logId.String())
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogout,
			Resource:     "user_impersonation",
			ResourceID:   originalUserID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to stop impersonation",
			ErrorMessage: err.Error(),
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.StopImpersonation; ERROR: %s;", logPrefix, err))

		statusCode, res := impersonationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}

	if tokenString, ok := ctx.Get("token"); ok {
		_ = h.Service.LogoutUser(reqCtx, tokenString.(string))
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionLogout,
		Resource:   "user_impersonation",
		ResourceID: originalUserID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Stopped impersonation session",
		Metadata: map[string]any{
			"impersonation_action": "stop",
			"restored_user_id":     originalUserID,
		},
	})

	res := gokit.Response(http.StatusOK, "Impersonation stopped successfully", logId, h.buildAuthTokenResponse(token, ""))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) GetAllUsers(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][GetAllUsers]"
	reqCtx := ctx.Request.Context()

	params, _ := gokit.GetBaseParams(ctx.Request.URL.Query(), "updated_at", "desc", 10)
	params.Filters = gokit.WhitelistFilter(params.Filters, []string{"role"})

	users, totalData, err := h.Service.GetAllUsers(reqCtx, httpshared.ActorFrom(reqCtx), httpshared.ListRequest(params))
	if err != nil {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; GetAllUsers; ERROR: %+v;", logPrefix, err))
		httpshared.RespondInternalError(ctx, logId)
		return
	}

	res := gokit.PaginationResponse(http.StatusOK, int(totalData), params.Page, params.Limit, logId, users)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(users)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) Update(ctx *gin.Context) {
	var req dtouser.UserUpdate
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][Update]"
	reqCtx := ctx.Request.Context()
	scope := domainauth.FromContext(reqCtx)

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logId)
		return
	}
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	h.updateUser(ctx, logId, logPrefix, scope.UserID, req, "Failed to update user profile", "Updated user profile")
}

func (h *Handler) UpdateUserById(ctx *gin.Context) {
	var req dtouser.UserUpdate
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][UpdateUserById]"

	id, err := gokit.ValidateUUIDParam(ctx, logId)
	if err != nil {
		return
	}
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", logPrefix, gokit.JsonEncode(req)))

	h.updateUser(ctx, logId, logPrefix, id, req, "Failed to update user by ID", "Updated user by ID")
}

func (h *Handler) ChangePassword(ctx *gin.Context) {
	var req dtouser.ChangePassword
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][ChangePassword]"
	reqCtx := ctx.Request.Context()
	scope := domainauth.FromContext(reqCtx)

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logId)
		return
	}
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	before, _ := h.Service.GetUserById(reqCtx, scope.UserID)
	data, err := h.Service.ChangePassword(reqCtx, scope.UserID, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user_password",
			ResourceID:   scope.UserID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to change password",
			ErrorMessage: err.Error(),
			BeforeData:   before,
			AfterData:    req,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.ChangePassword; ERROR: %s;", logPrefix, err))
		if !httpshared.IsNotFound(err) && err.Error() == ErrHashPassword {
			res := gokit.Response(http.StatusBadRequest, gokit.MsgSomethingWrong, logId, nil)
			res.Error = gokit.Errors{Code: http.StatusBadRequest, Message: "current password is incorrect"}
			ctx.JSON(http.StatusBadRequest, res)
			return
		}
		respondUserMutationError(ctx, logId, err)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "user_password",
		ResourceID: data.Id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Changed user password",
		BeforeData: before,
		AfterData: map[string]any{
			"user_id": data.Id,
		},
	})

	res := gokit.Response(http.StatusOK, "User password changed successfully", logId, data)
	logus.WriteLogWithContext(ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", logPrefix, gokit.JsonEncode(data)))
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) ForgotPassword(ctx *gin.Context) {
	var req dtouser.ForgotPasswordRequest
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][ForgotPassword]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	emailResetEnabled, ok := h.configEnabled(ctx, logId, logPrefix, h.Settings.Flags.PasswordResetEmail, false)
	if !ok {
		return
	}
	if emailResetEnabled {
		h.forgotPasswordByEmail(ctx, req, logId, logPrefix)
		return
	}

	appEnv := gokit.NormalizeKey(h.Settings.AppEnv)
	if !h.Settings.DevEnv {
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Development password reset fallback is disabled in APP_ENV=%s", logPrefix, appEnv))
		res := gokit.Response(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logId, nil)
		res.Error = gokit.Errors{Code: http.StatusServiceUnavailable, Message: "Password reset service is temporarily unavailable."}
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}

	token, err := h.Service.ForgotPassword(reqCtx, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user_password_reset",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to request password reset",
			ErrorMessage: err.Error(),
			AfterData: map[string]any{
				"email": req.Email,
			},
		})
		respondStepFailed(ctx, logId, logPrefix, "Service.ForgotPassword", err)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionUpdate,
		Resource: "user_password_reset",
		Status:   domainaudit.StatusSuccess,
		Message:  "Requested password reset",
		AfterData: map[string]any{
			"email": req.Email,
		},
	})

	logus.WriteLogWithContext(ctx, logus.LogLevelInfo, fmt.Sprintf("%s; Development password reset token generated for %s", logPrefix, gokit.SanitizeEmail(req.Email)))

	res := gokit.Response(http.StatusOK, "Password reset instructions sent to your email", logId, token)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) ResetPassword(ctx *gin.Context) {
	var req dtouser.ResetPasswordRequest
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][ResetPassword]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logId, logPrefix, &req) {
		return
	}

	emailResetEnabled, ok := h.configEnabled(ctx, logId, logPrefix, h.Settings.Flags.PasswordResetEmail, false)
	if !ok {
		return
	}
	if emailResetEnabled {
		h.resetPasswordByEmail(ctx, req, logId, logPrefix)
		return
	}

	if err := h.Service.ResetPassword(reqCtx, req); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user_password_reset",
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to reset password",
			ErrorMessage: err.Error(),
			AfterData:    req,
		})
		logus.WriteLogWithContext(ctx, logus.LogLevelError, fmt.Sprintf("%s; Service.ResetPassword; ERROR: %s;", logPrefix, err))
		statusCode, res := userMutationErrorResponse(logId, err)
		ctx.JSON(statusCode, res)
		return
	}
	if h.SessionSvc != nil {
		claims, err := h.Tokens.Claims(req.Token)
		if err != nil {
			respondStepFailed(ctx, logId, logPrefix, "JwtClaim after reset", err)
			return
		}
		if err := h.revokePasswordResetSessions(reqCtx, gokit.InterfaceString(claims["user_id"])); err != nil {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action:       domainaudit.ActionUpdate,
				Resource:     "user_password_reset",
				Status:       domainaudit.StatusFailed,
				Message:      "Failed to revoke sessions after password reset",
				ErrorMessage: err.Error(),
				AfterData:    req,
			})
			respondStepFailed(ctx, logId, logPrefix, "SessionSvc.DestroyAllUserSessions", err)
			return
		}
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionUpdate,
		Resource: "user_password_reset",
		Status:   domainaudit.StatusSuccess,
		Message:  "Reset password success",
		AfterData: map[string]any{
			"token": req.Token,
		},
	})

	res := gokit.Response(http.StatusOK, "Password reset successfully", logId, nil)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) revokePasswordResetSessions(ctx context.Context, userID string) error {
	if h.SessionSvc == nil || strings.TrimSpace(userID) == "" {
		return nil
	}

	return h.SessionSvc.DestroyAllUserSessions(ctx, userID)
}

func (h *Handler) Delete(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][Delete]"
	reqCtx := ctx.Request.Context()
	scope := domainauth.FromContext(reqCtx)

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logId)
		return
	}

	h.deleteUser(ctx, logId, logPrefix, scope.UserID, "Failed to delete own user", "Deleted own user")
}

func (h *Handler) DeleteUserById(ctx *gin.Context) {
	logId := gokit.GenerateLogId(ctx)
	logPrefix := "[UserHandler][DeleteUserById]"

	id, err := gokit.ValidateUUIDParam(ctx, logId)
	if err != nil {
		return
	}
	h.deleteUser(ctx, logId, logPrefix, id, "Failed to delete user by ID", "Deleted user by ID")
}
