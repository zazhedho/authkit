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
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
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

// Handler serves the user HTTP endpoints.
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

// Options are the optional dependencies and settings of the user handler.
type Options struct {
	AppConfigService AppConfigService
	OTPService       OTPService
	ResetService     ResetService
	Tokens           TokenIssuer
	Settings         Settings
}

// New creates the user handler.
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

// Register handles the register request.
func (h *Handler) Register(ctx *gin.Context) {
	var req dtouser.Register
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][Register]"
	reqCtx := ctx.Request.Context()

	if !h.registrationOpen(ctx, logID, logPrefix) {
		return
	}
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Request: %+v;", logPrefix, gokit.JSONEncode(gokit.RedactSensitivePayload(req)))

	otpEnabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.RegisterOTP, false)
	if !ok {
		return
	}
	if otpEnabled {
		if strings.TrimSpace(req.OTPCode) == "" {
			res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, "otp_code is required")
			ctx.JSON(http.StatusBadRequest, res)
			return
		}
		if h.OTPService == nil {
			res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, registrationOTPNotConfiguredMessage)
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
			res := gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, message)
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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.RegisterUser; Error: %+v", logPrefix, err)
		statusCode, res := userMutationErrorResponse(logID, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: data.ID,
		ActorRole:   data.Role,
		Action:      domainaudit.ActionCreate,
		Resource:    "user",
		ResourceID:  data.ID,
		Status:      domainaudit.StatusSuccess,
		Message:     "Registered user",
		AfterData:   userSnapshot(data),
	})

	res := gokit.Response(http.StatusCreated, "User registered successfully", logID, data)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(data))
	ctx.JSON(http.StatusCreated, res)
}

// GetRegisterStatus handles the get register status request.
func (h *Handler) GetRegisterStatus(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][GetRegisterStatus]"

	registerEnabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.PublicRegistration, true)
	if !ok {
		return
	}
	otpEnabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.RegisterOTP, false)
	if !ok {
		return
	}

	res := gokit.Response(http.StatusOK, "Get register status successfully", logID, map[string]any{
		"enabled":      registerEnabled,
		"otp_enabled":  otpEnabled,
		"otp_cooldown": int(h.Settings.OTPCooldown.Seconds()),
	})
	ctx.JSON(http.StatusOK, res)
}

// SendRegisterOTP handles the send register OTP request.
func (h *Handler) SendRegisterOTP(ctx *gin.Context) {
	var req dtouser.SendRegisterOTPRequest
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][SendRegisterOTP]"
	reqCtx := ctx.Request.Context()

	if !h.registrationOpen(ctx, logID, logPrefix) {
		return
	}
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	otpEnabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.RegisterOTP, false)
	if !ok {
		return
	}
	if !otpEnabled {
		res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, "registration OTP is disabled")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}
	if h.OTPService == nil {
		res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, registrationOTPNotConfiguredMessage)
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}

	normalizedEmail := domainuser.SanitizeEmail(req.Email)
	conflict, lookup, err := h.registrationConflict(reqCtx, normalizedEmail, req.Phone)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; %s; Error: %+v", logPrefix, lookup, err)
		httpshared.RespondInternalError(ctx, logID)
		return
	}
	if conflict != "" {
		res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgExists, logID, conflict)
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
			h.respondThrottle(ctx, logID, throttle.RetryAfter, "OTP request is throttled. Please try again later.")
			return
		}
		if errors.Is(err, domainotp.ErrNotConfigured) || errors.Is(err, domainotp.ErrDeliveryFailed) {
			statusCode := http.StatusServiceUnavailable
			res := gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, "Registration OTP service is temporarily unavailable.")
			ctx.JSON(statusCode, res)
			return
		}

		httpshared.RespondInternalError(ctx, logID)
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
	res := gokit.Response(http.StatusOK, "Registration OTP sent successfully", logID, nil)
	logus.LogContextf(ctx, logus.LevelInfo, "%s; Registration OTP sent successfully", logPrefix)
	ctx.JSON(http.StatusOK, res)
}

// AdminCreateUser handles the admin create user request.
func (h *Handler) AdminCreateUser(ctx *gin.Context) {
	var req dtouser.AdminCreateUser
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][AdminCreateUser]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Request: %+v;", logPrefix, gokit.JSONEncode(gokit.RedactSensitivePayload(req)))

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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.AdminCreateUser; Error: %+v", logPrefix, err)
		statusCode, res := userMutationErrorResponse(logID, err)
		ctx.JSON(statusCode, res)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionCreate,
		Resource:   "user",
		ResourceID: data.ID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Created user by admin",
		AfterData:  userSnapshot(data),
	})

	res := gokit.Response(http.StatusCreated, "User created successfully", logID, data)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(data))
	ctx.JSON(http.StatusCreated, res)
}

// Login handles the login request.
func (h *Handler) Login(ctx *gin.Context) {
	var req dtouser.Login
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserController][Login]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Request: %+v;", logPrefix, gokit.JSONEncode(gokit.RedactSensitivePayload(req)))

	normalizedIdentifier, err := domainuser.ResolveLoginIdentifier(req.Identifier, req.Email)
	if err != nil {
		res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, err.Error())
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	loginIdentifier := fmt.Sprintf("%s:%s", ctx.ClientIP(), normalizedIdentifier)
	if h.rejectBlockedLogin(ctx, logID, logPrefix, loginIdentifier, normalizedIdentifier) {
		return
	}

	token, err := h.Service.LoginUser(reqCtx, req, logID.String(), dtouser.LoginMetadata{
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	})
	if err != nil {
		h.handleLoginFailure(ctx, logID, logPrefix, normalizedIdentifier, loginIdentifier, err)
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
		loginUserID = loggedInUser.ID
	}

	refreshToken := ""
	if userErr == nil {
		refreshToken, err = h.Tokens.GenerateRefresh(loggedInUser.ID, loggedInUser.Name, loggedInUser.Role, logID.String())
		if err != nil {
			respondStepFailed(ctx, logID, logPrefix, "GenerateRefreshJwt", err)
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
	res := gokit.Response(http.StatusOK, "success", logID, data)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(gokit.RedactSensitivePayload(data)))
	ctx.JSON(http.StatusOK, res)
}

// GoogleLogin handles the google login request.
func (h *Handler) GoogleLogin(ctx *gin.Context) {
	var req dtouser.GoogleLogin
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][GoogleLogin]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	registerEnabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.PublicRegistration, true)
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

		res := gokit.InternalServerError(logID)
		switch {
		case errors.Is(err, domainuser.ErrGoogleNotConfigured):
			res = gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, "Google login is not configured.")
		case errors.Is(err, domainuser.ErrGoogleTokenInvalid):
			res = gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, "Invalid Google token.")
		case errors.Is(err, domainuser.ErrGoogleEmailMissing):
			res = gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, "Google account email is not available.")
		case errors.Is(err, domainuser.ErrPublicRegistrationDisabled):
			res = gokit.Forbidden(logID, publicRegistrationDisabledMessage)
		}
		ctx.JSON(statusCode, res)
		return
	}

	accessToken, err := h.Tokens.Generate(user.ID, user.Name, user.Role, logID.String())
	if err != nil {
		respondStepFailed(ctx, logID, logPrefix, "GenerateJwt", err)
		return
	}

	refreshToken, err := h.Tokens.GenerateRefresh(user.ID, user.Name, user.Role, logID.String())
	if err != nil {
		respondStepFailed(ctx, logID, logPrefix, "GenerateRefreshJwt", err)
		return
	}

	if h.SessionSvc != nil {
		session, errSession := h.SessionSvc.CreateSession(reqCtx, &user, accessToken, refreshToken, domainsession.RequestMeta{
			IP:        ctx.ClientIP(),
			UserAgent: ctx.GetHeader("User-Agent"),
		})
		if errSession != nil {
			logus.LogContextf(ctx, logus.LevelError, "%s; Failed to create session: %v", logPrefix, errSession)
		} else {
			logus.LogContextf(ctx, logus.LevelInfo, "%s; Session created: %s", logPrefix, session.SessionID)
		}
	}

	successMessage := "Google login success"
	if isNewUser {
		successMessage = "Google registration success"
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		ActorUserID: user.ID,
		ActorRole:   user.Role,
		Action:      domainaudit.ActionLogin,
		Resource:    "auth",
		ResourceID:  user.ID,
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

	res := gokit.Response(http.StatusOK, successMessage, logID, data)
	logus.LogContextf(ctx, logus.LevelInfo, "%s; %s; Data: %+v", logPrefix, successMessage, gokit.JSONEncode(gokit.RedactSensitivePayload(data)))
	ctx.JSON(http.StatusOK, res)
}

// RefreshToken handles the refresh token request.
func (h *Handler) RefreshToken(ctx *gin.Context) {
	var req dtouser.RefreshTokenRequest
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][RefreshToken]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	tokenClaims, err := h.Tokens.Claims(req.RefreshToken)
	if err != nil {
		h.rejectRefresh(ctx, logID, "invalid or expired refresh token", domainaudit.AuditEvent{
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token is invalid or expired",
		})
		return
	}

	claimUserID := gokit.InterfaceString(tokenClaims["user_id"])
	claimRole := gokit.InterfaceString(tokenClaims["role"])
	if !strings.EqualFold(gokit.InterfaceString(tokenClaims["token_type"]), "refresh") {
		h.rejectRefresh(ctx, logID, "invalid token type", domainaudit.AuditEvent{
			ActorUserID:  claimUserID,
			ActorRole:    claimRole,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The provided token is not a refresh token",
		})
		return
	}

	isBlacklisted, err := h.Service.IsTokenRevoked(ctx.Request.Context(), req.RefreshToken)
	if err != nil {
		h.failRefresh(ctx, logID, logPrefix, "BlacklistRepo.ExistsByToken", err, domainaudit.AuditEvent{
			ActorUserID: claimUserID,
			ActorRole:   claimRole,
			Message:     "Failed to validate login session renewal",
		})
		return
	}
	if isBlacklisted {
		h.rejectRefresh(ctx, logID, "refresh token has been revoked", domainaudit.AuditEvent{
			ActorUserID:  claimUserID,
			ActorRole:    claimRole,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token has already been revoked",
		})
		return
	}

	userID := claimUserID
	user, err := h.Service.GetUserByID(reqCtx, userID)
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
		res := gokit.ErrorResponse(statusCode, gokit.MsgSomethingWrong, logID, userNotFoundMessage)
		ctx.JSON(statusCode, res)
		return
	}

	imp := impersonationFromClaims(tokenClaims)
	accessToken, err := h.issueAccessToken(&user, logID.String(), imp)
	if err != nil {
		h.failRefresh(ctx, logID, logPrefix, "GenerateJwtWithClaims", err, domainaudit.AuditEvent{
			ActorUserID: userID,
			ActorRole:   user.Role,
			ResourceID:  userID,
			Message:     "Failed to issue a new access token",
		})
		return
	}

	refreshToken, err := h.issueRefreshToken(&user, logID.String(), imp)
	if err != nil {
		h.failRefresh(ctx, logID, logPrefix, "GenerateRefreshJwt", err, domainaudit.AuditEvent{
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
			logus.LogContextf(ctx, logus.LevelError, "%s; SessionSvc.GetSessionByRefreshToken; ERROR: %s;", logPrefix, sessionErr)
			respondRefreshUnauthorized(ctx, logID, "session not found for refresh token")
			return
		}

		refreshExpAt := time.Now().Add(h.Settings.RefreshTTL)
		if sessionErr = h.SessionSvc.RotateSessionTokens(reqCtx, session.SessionID, accessToken, refreshToken, refreshExpAt); sessionErr != nil {
			h.failRefresh(ctx, logID, logPrefix, "SessionSvc.RotateSessionTokens", sessionErr, domainaudit.AuditEvent{
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
		h.failRefresh(ctx, logID, logPrefix, "Service.LogoutUser(refresh)", err, domainaudit.AuditEvent{
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

	res := gokit.Response(http.StatusOK, "Refresh token rotated successfully", logID, h.buildAuthTokenResponse(accessToken, refreshToken))
	ctx.JSON(http.StatusOK, res)
}

// Logout handles the logout request.
func (h *Handler) Logout(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
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
		logus.LogContextf(ctx, logus.LevelError, "%s; token not found in context", logPrefix)
		httpshared.RespondInternalError(ctx, logID)
		return
	}

	if h.SessionSvc != nil {
		errSession := h.SessionSvc.DestroySessionByToken(reqCtx, token.(string))
		if errSession != nil {
			logus.LogContextf(ctx, logus.LevelError, "%s; Failed to destroy session: %v", logPrefix, errSession)
		} else {
			logus.LogContextf(ctx, logus.LevelInfo, "%s; Session destroyed successfully", logPrefix)
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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.LogoutUser; Error: %+v", logPrefix, err)
		httpshared.RespondInternalError(ctx, logID)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionLogout,
		Resource: "auth",
		Status:   domainaudit.StatusSuccess,
		Message:  "Logout success",
	})

	res := gokit.Response(http.StatusOK, "User logged out successfully", logID, nil)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Success: User logged out successfully", logPrefix)
	ctx.JSON(http.StatusOK, res)
}

// GetUserByID handles the get user by ID request.
func (h *Handler) GetUserByID(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][GetUserByID]"
	reqCtx := ctx.Request.Context()

	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return
	}

	data, err := h.Service.GetUserByID(reqCtx, id)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.GetUserByID; ERROR: %s;", logPrefix, err)
		respondUserLookupError(ctx, logID, err)
		return
	}

	res := gokit.Response(http.StatusOK, "success", logID, data)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(data))
	ctx.JSON(http.StatusOK, res)
}

// GetUserByAuth handles the get user by auth request.
func (h *Handler) GetUserByAuth(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][GetUserByAuth]"
	reqCtx := ctx.Request.Context()
	scope := domainauth.FromContext(reqCtx)

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logID)
		return
	}

	data, err := h.Service.GetUserByAuth(reqCtx, scope.UserID)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.GetUserByAuth; ERROR: %s;", logPrefix, err)
		respondUserLookupError(ctx, logID, err)
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

	res := gokit.Response(http.StatusOK, "success", logID, data)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(data))
	ctx.JSON(http.StatusOK, res)
}

// ImpersonateUser handles the impersonate user request.
func (h *Handler) ImpersonateUser(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][ImpersonateUser]"
	reqCtx := ctx.Request.Context()

	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return
	}

	var body dtouser.Impersonate
	if !gokit.BindJSON(ctx, logID, logPrefix, &body) {
		return
	}
	reason := strings.TrimSpace(body.Reason)

	token, err := h.Service.ImpersonateUser(reqCtx, httpshared.ActorFrom(reqCtx), id, reason, logID.String())
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
				"reason":         reason,
			},
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.ImpersonateUser; ERROR: %s;", logPrefix, err)

		statusCode, res := impersonationErrorResponse(logID, err)
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
			"reason":         reason,
		},
		Metadata: map[string]any{
			"impersonation_action": "start",
			"target_user_id":       id,
		},
	})

	res := gokit.Response(http.StatusOK, "Impersonation started successfully", logID, h.buildAuthTokenResponse(token, ""))
	ctx.JSON(http.StatusOK, res)
}

// StopImpersonation handles the stop impersonation request.
func (h *Handler) StopImpersonation(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][StopImpersonation]"
	reqCtx := ctx.Request.Context()

	scope := domainauth.FromContext(reqCtx)
	originalUserID := scope.OriginalUserID
	if !scope.IsImpersonated || originalUserID == "" {
		res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, "current session is not impersonated")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	token, err := h.Service.StopImpersonation(reqCtx, httpshared.ActorFrom(reqCtx), logID.String())
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionLogout,
			Resource:     "user_impersonation",
			ResourceID:   originalUserID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to stop impersonation",
			ErrorMessage: err.Error(),
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.StopImpersonation; ERROR: %s;", logPrefix, err)

		statusCode, res := impersonationErrorResponse(logID, err)
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

	res := gokit.Response(http.StatusOK, "Impersonation stopped successfully", logID, h.buildAuthTokenResponse(token, ""))
	ctx.JSON(http.StatusOK, res)
}

// GetAllUsers handles the get all users request.
func (h *Handler) GetAllUsers(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][GetAllUsers]"
	reqCtx := ctx.Request.Context()

	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "updated_at", "desc", 10)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; GetBaseParams; ERROR: %+v;", logPrefix, err)
		ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, "invalid query parameters"))
		return
	}
	params.Filters = gokit.WhitelistFilter(params.Filters, []string{"role"})

	users, totalData, err := h.Service.GetAllUsers(reqCtx, httpshared.ActorFrom(reqCtx), httpshared.ListRequest(params))
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; GetAllUsers; ERROR: %+v;", logPrefix, err)
		httpshared.RespondInternalError(ctx, logID)
		return
	}

	res := gokit.PaginationResponse(http.StatusOK, totalData, params.Page, httpshared.PageSize(dtoshared.PagedList, params), logID, users)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(users))
	ctx.JSON(http.StatusOK, res)
}

// Update handles the update request.
func (h *Handler) Update(ctx *gin.Context) {
	var req dtouser.Update
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][Update]"
	reqCtx := ctx.Request.Context()
	scope := domainauth.FromContext(reqCtx)

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logID)
		return
	}
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	h.updateUser(ctx, logID, logPrefix, scope.UserID, req, "Failed to update user profile", "Updated user profile")
}

// UpdateUserByID handles the update user by id request.
func (h *Handler) UpdateUserByID(ctx *gin.Context) {
	var req dtouser.Update
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][UpdateUserById]"

	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return
	}
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Request: %+v;", logPrefix, gokit.JSONEncode(req))

	h.updateUser(ctx, logID, logPrefix, id, req, "Failed to update user by ID", "Updated user by ID")
}

// ChangePassword handles the change password request.
func (h *Handler) ChangePassword(ctx *gin.Context) {
	var req dtouser.ChangePassword
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][ChangePassword]"
	reqCtx := ctx.Request.Context()
	scope := domainauth.FromContext(reqCtx)

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logID)
		return
	}
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	before, _ := h.Service.GetUserByID(reqCtx, scope.UserID)
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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.ChangePassword; ERROR: %s;", logPrefix, err)
		if !httpshared.IsNotFound(err) && err.Error() == ErrHashPassword {
			res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgSomethingWrong, logID, "current password is incorrect")
			ctx.JSON(http.StatusBadRequest, res)
			return
		}
		respondUserMutationError(ctx, logID, err)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "user_password",
		ResourceID: data.ID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Changed user password",
		BeforeData: before,
		AfterData: map[string]any{
			"user_id": data.ID,
		},
	})

	res := gokit.Response(http.StatusOK, "User password changed successfully", logID, data)
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(data))
	ctx.JSON(http.StatusOK, res)
}

// ForgotPassword handles the forgot password request.
func (h *Handler) ForgotPassword(ctx *gin.Context) {
	var req dtouser.ForgotPasswordRequest
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][ForgotPassword]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	emailResetEnabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.PasswordResetEmail, false)
	if !ok {
		return
	}
	if emailResetEnabled {
		h.forgotPasswordByEmail(ctx, req, logID, logPrefix)
		return
	}

	appEnv := httpshared.NormalizeKey(h.Settings.AppEnv)
	if !h.Settings.DevEnv {
		logus.LogContextf(ctx, logus.LevelError, "%s; Development password reset fallback is disabled in APP_ENV=%s", logPrefix, appEnv)
		res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, "Password reset service is temporarily unavailable.")
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
		respondStepFailed(ctx, logID, logPrefix, "Service.ForgotPassword", err)
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

	logus.LogContextf(ctx, logus.LevelInfo, "%s; Development password reset token generated for %s", logPrefix, domainuser.SanitizeEmail(req.Email))

	res := gokit.Response(http.StatusOK, "Password reset instructions sent to your email", logID, token)
	ctx.JSON(http.StatusOK, res)
}

// ResetPassword handles the reset password request.
func (h *Handler) ResetPassword(ctx *gin.Context) {
	var req dtouser.ResetPasswordRequest
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][ResetPassword]"
	reqCtx := ctx.Request.Context()
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	emailResetEnabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.PasswordResetEmail, false)
	if !ok {
		return
	}
	if emailResetEnabled {
		h.resetPasswordByEmail(ctx, req, logID, logPrefix)
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
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.ResetPassword; ERROR: %s;", logPrefix, err)
		statusCode, res := userMutationErrorResponse(logID, err)
		ctx.JSON(statusCode, res)
		return
	}
	if h.SessionSvc != nil {
		claims, err := h.Tokens.Claims(req.Token)
		if err != nil {
			respondStepFailed(ctx, logID, logPrefix, "JwtClaim after reset", err)
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
			respondStepFailed(ctx, logID, logPrefix, "SessionSvc.DestroyAllUserSessions", err)
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

	res := gokit.Response(http.StatusOK, "Password reset successfully", logID, nil)
	ctx.JSON(http.StatusOK, res)
}

func (h *Handler) revokePasswordResetSessions(ctx context.Context, userID string) error {
	return h.revokeAllSessions(ctx, userID)
}

func (h *Handler) revokeAllSessions(ctx context.Context, userID string) error {
	if h.SessionSvc == nil || strings.TrimSpace(userID) == "" {
		return nil
	}

	return h.SessionSvc.DestroyAllUserSessions(ctx, userID)
}

// Delete handles the delete request.
func (h *Handler) Delete(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][Delete]"
	reqCtx := ctx.Request.Context()
	scope := domainauth.FromContext(reqCtx)

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logID)
		return
	}

	h.deleteUser(ctx, logID, logPrefix, scope.UserID, "Failed to delete own user", "Deleted own user")
}

// DeleteUserByID handles the delete user by id request.
func (h *Handler) DeleteUserByID(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][DeleteUserById]"

	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return
	}
	h.deleteUser(ctx, logID, logPrefix, id, "Failed to delete user by ID", "Deleted user by ID")
}
