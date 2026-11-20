package user

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	AppEnv, EmailAppName  string
	AccessTTL, RefreshTTL time.Duration
	// SessionMaxLifetime is the absolute cap on a session, counted from login
	// and not extended by refresh; zero means no cap.
	SessionMaxLifetime time.Duration
	// FailClosedLimiters rejects a request when the login limiter cannot be
	// reached instead of letting it through.
	FailClosedLimiters bool
	OTPCooldown        time.Duration
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
	// IdentifierLimiter backs off failures per identifier across all clients.
	IdentifierLimiter LoginLimiter
	// Async runs the mail sends after the response; nil runs them inline.
	Async AsyncRunner
}

// Options are the optional dependencies and settings of the user handler.
type Options struct {
	// Async runs the mail sends after the response; nil runs them inline.
	Async AsyncRunner
	// IdentifierLimiter counts failures per identifier across all clients,
	// with a backoff instead of a lockout; nil is off.
	IdentifierLimiter LoginLimiter
	AppConfigService  AppConfigService
	OTPService        OTPService
	ResetService      ResetService
	Tokens            TokenIssuer
	Settings          Settings
}

func New(
	s Service,
	sessionSvc SessionService,
	limiter LoginLimiter,
	auditService httpshared.AuditService,
	options Options,
) *Handler {
	return &Handler{
		Service:           s,
		SessionSvc:        sessionSvc,
		LoginLimiter:      limiter,
		AuditWriter:       httpshared.NewAuditWriter(auditService, "UserHandler"),
		AppConfigService:  options.AppConfigService,
		OTPService:        options.OTPService,
		ResetService:      options.ResetService,
		Tokens:            options.Tokens,
		Settings:          options.Settings,
		Async:             options.Async,
		IdentifierLimiter: options.IdentifierLimiter,
	}
}

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

	res := gokit.Response(http.StatusCreated, "User registered successfully", logID, dtouser.NewResponse(data, false))
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(gokit.RedactSensitivePayload(data)))
	ctx.JSON(http.StatusCreated, res)
}

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

	// The answer never depends on whether the address is taken, throttled or
	// deliverable, so the route cannot be used to find out which emails exist.
	// The send itself happens after the response and only logs failures.
	if conflict == "" && normalizedEmail != "" {
		appName := h.Settings.EmailAppName
		h.runAsync(ctx, logID, func(bg context.Context) {
			if err := h.OTPService.SendRegisterOTP(bg, normalizedEmail, appName); err != nil {
				logus.LogContextf(bg, logus.LevelError, "%s; OTPService.SendRegisterOTP; ERROR: %s;", logPrefix, err)
			}
		})
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:   domainaudit.ActionCreate,
		Resource: "user_registration_otp",
		Status:   domainaudit.StatusSuccess,
		Message:  "Requested registration OTP",
		AfterData: map[string]any{
			"email": normalizedEmail,
		},
	})
	res := gokit.Response(http.StatusOK, registrationOTPAcceptedMessage, logID, nil)
	ctx.JSON(http.StatusOK, res)
}

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

	res := gokit.Response(http.StatusCreated, "User created successfully", logID, dtouser.NewResponse(data, false))
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(gokit.RedactSensitivePayload(data)))
	ctx.JSON(http.StatusCreated, res)
}

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
	if h.rejectBlockedLogin(ctx, logID, logPrefix, h.LoginLimiter, loginIdentifier, normalizedIdentifier) ||
		h.rejectBlockedLogin(ctx, logID, logPrefix, h.IdentifierLimiter, identifierKey(normalizedIdentifier), normalizedIdentifier) {
		return
	}

	token, err := h.Service.LoginUser(reqCtx, req, dtouser.LoginMetadata{
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
	if userErr != nil {
		respondStepFailed(ctx, logID, logPrefix, "Service.GetUser", userErr)
		return
	}
	loginUserID := loggedInUser.ID

	refreshToken, err := h.Tokens.GenerateRefresh(loggedInUser.ID, loggedInUser.Name, loggedInUser.Role, issuedAfter(loggedInUser))
	if err != nil {
		respondStepFailed(ctx, logID, logPrefix, "GenerateRefreshJwt", err)
		return
	}

	h.resetLoginLimiter(ctx, logPrefix, h.LoginLimiter, loginIdentifier)
	h.resetLoginLimiter(ctx, logPrefix, h.IdentifierLimiter, identifierKey(normalizedIdentifier))
	if err := h.createLoginSession(ctx, reqCtx, &loggedInUser, token, refreshToken, logPrefix); err != nil {
		respondStepFailed(ctx, logID, logPrefix, "SessionSvc.CreateSession", err)
		return
	}

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

	accessToken, err := h.Tokens.Generate(user.ID, user.Name, user.Role, issuedAfter(user))
	if err != nil {
		respondStepFailed(ctx, logID, logPrefix, "GenerateJwt", err)
		return
	}

	refreshToken, err := h.Tokens.GenerateRefresh(user.ID, user.Name, user.Role, issuedAfter(user))
	if err != nil {
		respondStepFailed(ctx, logID, logPrefix, "GenerateRefreshJwt", err)
		return
	}

	if err := h.createLoginSession(ctx, reqCtx, &user, accessToken, refreshToken, logPrefix); err != nil {
		respondStepFailed(ctx, logID, logPrefix, "SessionSvc.CreateSession", err)
		return
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

	userID := claimUserID
	// With sessions the session index is the one replay mechanism: a rotated
	// token that comes back revokes the whole session. Without sessions the
	// blacklist claims each refresh token once.
	var session *domainsession.Session
	if h.SessionSvc != nil {
		var sessionErr error
		session, sessionErr = h.SessionSvc.GetSessionByRefreshToken(reqCtx, req.RefreshToken)
		if sessionErr != nil {
			message := "No active session was found for the refresh token"
			if errors.Is(sessionErr, domainsession.ErrRefreshReused) {
				message = "A rotated refresh token was presented again; the session was revoked"
			} else if !errors.Is(sessionErr, domainsession.ErrNotFound) {
				h.failRefresh(ctx, logID, logPrefix, "SessionSvc.GetSessionByRefreshToken", sessionErr, domainaudit.AuditEvent{
					ActorUserID: userID, ActorRole: claimRole, Message: "Failed to look up the login session",
				})
				return
			}
			h.rejectRefresh(ctx, logID, "session not found for refresh token", domainaudit.AuditEvent{
				ActorUserID: userID, ActorRole: claimRole, ResourceID: userID,
				Message: failedRenewLoginSessionMessage, ErrorMessage: message,
			})
			return
		}
	} else {
		isBlacklisted, err := h.Service.IsTokenRevoked(reqCtx, req.RefreshToken)
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
	}

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

	if user.TokensValidAfter != nil && domainauth.RevokedBy(tokenClaims, *user.TokensValidAfter) {
		h.rejectRefresh(ctx, logID, "refresh token has been revoked", domainaudit.AuditEvent{
			ActorUserID:  userID,
			ActorRole:    user.Role,
			Message:      failedRenewLoginSessionMessage,
			ErrorMessage: "The refresh token was issued before the account's tokens were revoked",
		})
		return
	}

	if h.SessionSvc == nil {
		// Claim the old refresh token: the blacklist has a unique key, so of two
		// concurrent refreshes only one gets past this point.
		if err = h.Service.LogoutUser(reqCtx, req.RefreshToken); err != nil {
			if errors.Is(err, domainauth.ErrDuplicate) {
				h.rejectRefresh(ctx, logID, "refresh token has been revoked", domainaudit.AuditEvent{
					ActorUserID:  userID,
					ActorRole:    user.Role,
					Message:      failedRenewLoginSessionMessage,
					ErrorMessage: "The refresh token was already used",
				})
				return
			}
			h.failRefresh(ctx, logID, logPrefix, "Service.LogoutUser(refresh)", err, domainaudit.AuditEvent{
				ActorUserID: userID,
				ActorRole:   user.Role,
				ResourceID:  userID,
				Message:     "Failed to revoke previous login session token",
			})
			return
		}
	}

	accessToken, err := h.Tokens.Generate(user.ID, user.Name, user.Role, issuedAfter(user))
	if err != nil {
		h.failRefresh(ctx, logID, logPrefix, "GenerateJwtWithClaims", err, domainaudit.AuditEvent{
			ActorUserID: userID,
			ActorRole:   user.Role,
			ResourceID:  userID,
			Message:     "Failed to issue a new access token",
		})
		return
	}

	refreshToken, err := h.Tokens.GenerateRefresh(user.ID, user.Name, user.Role, issuedAfter(user))
	if err != nil {
		h.failRefresh(ctx, logID, logPrefix, "GenerateRefreshJwt", err, domainaudit.AuditEvent{
			ActorUserID: userID,
			ActorRole:   user.Role,
			ResourceID:  userID,
			Message:     "Failed to issue a new refresh token",
		})
		return
	}

	if session != nil {
		refreshExpAt, withinCap := h.sessionExpiry(session.LoginAt)
		if !withinCap {
			if destroyErr := h.SessionSvc.DestroySession(reqCtx, session.SessionID); destroyErr != nil {
				logus.LogContextf(ctx, logus.LevelError, "%s; SessionSvc.DestroySession; ERROR: %s;", logPrefix, destroyErr)
			}
			h.rejectRefresh(ctx, logID, "session has reached its maximum lifetime", domainaudit.AuditEvent{
				ActorUserID:  userID,
				ActorRole:    user.Role,
				Message:      failedRenewLoginSessionMessage,
				ErrorMessage: "The session exceeded its absolute lifetime",
			})
			return
		}
		if sessionErr := h.SessionSvc.RotateSessionTokens(reqCtx, session.SessionID, accessToken, refreshToken, refreshExpAt); sessionErr != nil {
			if errors.Is(sessionErr, domainsession.ErrRefreshReused) {
				h.rejectRefresh(ctx, logID, "refresh token has been revoked", domainaudit.AuditEvent{
					ActorUserID:  userID,
					ActorRole:    user.Role,
					Message:      failedRenewLoginSessionMessage,
					ErrorMessage: "The refresh token was used concurrently; the session was revoked",
				})
				return
			}
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

	var body dtouser.Logout
	if err := ctx.ShouldBindJSON(&body); err != nil && !errors.Is(err, io.EOF) {
		res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, "invalid request body")
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	if h.SessionSvc != nil {
		if errSession := h.SessionSvc.DestroySessionByToken(reqCtx, token.(string)); errSession != nil && !errors.Is(errSession, domainsession.ErrNotFound) {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action:       domainaudit.ActionLogout,
				Resource:     "auth",
				Status:       domainaudit.StatusFailed,
				Message:      "Logout failed to destroy the session",
				ErrorMessage: errSession.Error(),
			})
			logus.LogContextf(ctx, logus.LevelError, "%s; Failed to destroy session: %v", logPrefix, errSession)
			httpshared.RespondInternalError(ctx, logID)
			return
		}
	}

	if refresh := strings.TrimSpace(body.RefreshToken); refresh != "" {
		if err := h.revokeRefreshToken(reqCtx, domainauth.FromContext(reqCtx).UserID, refresh); err != nil {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action:       domainaudit.ActionLogout,
				Resource:     "auth",
				Status:       domainaudit.StatusFailed,
				Message:      "Logout failed to revoke the refresh token",
				ErrorMessage: err.Error(),
			})
			logus.LogContextf(ctx, logus.LevelError, "%s; revoke refresh token: %v", logPrefix, err)
			httpshared.RespondInternalError(ctx, logID)
			return
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

func (h *Handler) GetUserByID(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][GetUserByID]"
	reqCtx := ctx.Request.Context()

	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return
	}

	actor := httpshared.ActorFrom(reqCtx)
	user, err := h.Service.GetUserForActor(reqCtx, actor, id)
	if err != nil {
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.GetUserForActor; ERROR: %s;", logPrefix, err)
		respondUserLookupError(ctx, logID, err)
		return
	}

	data := dtouser.NewResponse(user, actor.Role == domainuser.RoleSuperAdmin)
	res := gokit.Response(http.StatusOK, "success", logID, data)
	ctx.JSON(http.StatusOK, res)
}

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
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Response: %+v;", logPrefix, gokit.JSONEncode(gokit.RedactSensitivePayload(data)))
	ctx.JSON(http.StatusOK, res)
}

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

	token, err := h.Service.ImpersonateUser(reqCtx, httpshared.ActorFrom(reqCtx), id, reason, h.actorBinding(ctx, reqCtx))
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

	// The token is released only once the start is on record.
	if err := h.WriteAuditStrict(ctx, domainaudit.AuditEvent{
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
	}); err != nil {
		respondStepFailed(ctx, logID, logPrefix, "audit", err)
		return
	}

	res := gokit.Response(http.StatusOK, "Impersonation started successfully", logID, h.buildAuthTokenResponse(token, ""))
	ctx.JSON(http.StatusOK, res)
}

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

	if !h.actorSessionLive(ctx, reqCtx, logID) {
		return
	}

	token, err := h.Service.StopImpersonation(reqCtx, httpshared.ActorFrom(reqCtx), domainauth.IssuedAtMillis(httpshared.GetAuthData(reqCtx)))
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

	// The impersonation token must stop working before the original identity
	// is handed back; a failure here is an error, not a log line.
	if tokenString, ok := ctx.Get("token"); ok {
		if err := h.Service.LogoutUser(reqCtx, tokenString.(string)); err != nil && !errors.Is(err, domainauth.ErrDuplicate) {
			h.WriteAudit(ctx, domainaudit.AuditEvent{
				Action:       domainaudit.ActionLogout,
				Resource:     "user_impersonation",
				ResourceID:   originalUserID,
				Status:       domainaudit.StatusFailed,
				Message:      "Failed to revoke the impersonation token",
				ErrorMessage: err.Error(),
			})
			respondStepFailed(ctx, logID, logPrefix, "Service.LogoutUser", err)
			return
		}
	}

	if err := h.WriteAuditStrict(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionLogout,
		Resource:   "user_impersonation",
		ResourceID: originalUserID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Stopped impersonation session",
		Metadata: map[string]any{
			"impersonation_action": "stop",
			"restored_user_id":     originalUserID,
		},
	}); err != nil {
		respondStepFailed(ctx, logID, logPrefix, "audit", err)
		return
	}

	res := gokit.Response(http.StatusOK, "Impersonation stopped successfully", logID, h.buildAuthTokenResponse(token, ""))
	ctx.JSON(http.StatusOK, res)
}

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

	actor := httpshared.ActorFrom(reqCtx)
	items := dtouser.NewResponses(users, actor.Role == domainuser.RoleSuperAdmin)
	res := gokit.PaginationResponse(http.StatusOK, totalData, params.Page, httpshared.PageSize(dtoshared.PagedList, params), logID, items)
	ctx.JSON(http.StatusOK, res)
}

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
	if h.denyWhileImpersonating(ctx, logID, scope, "user", "update the profile") {
		return
	}
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	h.updateUser(ctx, logID, logPrefix, scope.UserID, req, "Failed to update user profile", "Updated user profile")
}

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
	logus.LogContextf(ctx, logus.LevelDebug, "%s; Request: %+v;", logPrefix, gokit.JSONEncode(gokit.RedactSensitivePayload(req)))

	h.updateUser(ctx, logID, logPrefix, id, req, "Failed to update user by ID", "Updated user by ID")
}

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
	if h.denyWhileImpersonating(ctx, logID, scope, "user_password", "change password") {
		return
	}
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	limiterKey := "change_password:" + scope.UserID
	if h.rejectBlockedLogin(ctx, logID, logPrefix, h.LoginLimiter, limiterKey, scope.UserID) {
		return
	}

	before, _ := h.Service.GetUserByID(reqCtx, scope.UserID)
	cutoff, err := h.Service.ChangePassword(reqCtx, scope.UserID, req)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user_password",
			ResourceID:   scope.UserID,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to change password",
			ErrorMessage: err.Error(),
			BeforeData:   userSnapshot(before),
		})
		logus.LogContextf(ctx, logus.LevelError, "%s; Service.ChangePassword; ERROR: %s;", logPrefix, err)
		if errors.Is(err, domainuser.ErrPasswordIncorrect) {
			blocked, responded := h.registerLimiterFailure(ctx, logID, logPrefix, limiterKey)
			if responded {
				return
			}
			if blocked {
				h.respondTooManyLoginAttempts(ctx, logID, 0)
				return
			}
		}
		respondUserMutationError(ctx, logID, err)
		return
	}
	h.resetLoginLimiter(ctx, logPrefix, h.LoginLimiter, limiterKey)

	// Every older token is void; the caller gets a fresh pair issued after the
	// cut-off and, with sessions, keeps only that one session.
	user, err := h.Service.GetUserByID(reqCtx, scope.UserID)
	if err != nil {
		respondStepFailed(ctx, logID, logPrefix, "Service.GetUserByID", err)
		return
	}
	accessToken, err := h.Tokens.Generate(user.ID, user.Name, user.Role, cutoff)
	if err != nil {
		respondStepFailed(ctx, logID, logPrefix, "GenerateJwt", err)
		return
	}
	refreshToken, err := h.Tokens.GenerateRefresh(user.ID, user.Name, user.Role, cutoff)
	if err != nil {
		respondStepFailed(ctx, logID, logPrefix, "GenerateRefreshJwt", err)
		return
	}
	if err := h.reissueSession(ctx, reqCtx, &user, accessToken, refreshToken, logPrefix); err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     "user_password",
			ResourceID:   scope.UserID,
			Status:       domainaudit.StatusFailed,
			Message:      "Password changed but the session could not be re-issued",
			ErrorMessage: err.Error(),
		})
		respondStepFailed(ctx, logID, logPrefix, "reissueSession", err)
		return
	}
	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   "user_password",
		ResourceID: user.ID,
		Status:     domainaudit.StatusSuccess,
		Message:    "Changed user password",
		AfterData: map[string]any{
			"user_id": user.ID,
		},
	})

	data := h.buildAuthTokenResponse(accessToken, refreshToken)
	data["user"] = dtouser.NewResponse(user, false)
	res := gokit.Response(http.StatusOK, "User password changed successfully", logID, data)
	ctx.JSON(http.StatusOK, res)
}

// ForgotPassword handles the forgot password request. It answers 200 whether
// or not the email is registered and whether or not mail could be sent, so the
// route reveals nothing about which emails exist; failures are logged.
func (h *Handler) ForgotPassword(ctx *gin.Context) {
	var req dtouser.ForgotPasswordRequest
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][ForgotPassword]"
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

	logus.LogContextf(ctx, logus.LevelWarn, "%s; password reset by email is disabled; the request was ignored", logPrefix)
	ctx.JSON(http.StatusOK, gokit.Response(http.StatusOK, forgotPasswordMessage, logID, nil))
}

func (h *Handler) ResetPassword(ctx *gin.Context) {
	var req dtouser.ResetPasswordRequest
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][ResetPassword]"
	if !gokit.BindJSON(ctx, logID, logPrefix, &req) {
		return
	}

	emailResetEnabled, ok := h.configEnabled(ctx, logID, logPrefix, h.Settings.Flags.PasswordResetEmail, false)
	if !ok {
		return
	}
	if !emailResetEnabled {
		res := gokit.ErrorResponse(http.StatusServiceUnavailable, gokit.MsgSomethingWrong, logID, passwordResetEmailNotConfiguredMessage)
		ctx.JSON(http.StatusServiceUnavailable, res)
		return
	}
	h.resetPasswordByEmail(ctx, req, logID, logPrefix)
}

func (h *Handler) Delete(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][Delete]"
	scope := domainauth.FromContext(ctx.Request.Context())

	if scope.UserID == "" {
		httpshared.RespondUnauthorized(ctx, logID)
		return
	}

	if h.denyWhileImpersonating(ctx, logID, scope, "user", "delete the account") {
		return
	}
	if !h.confirmOwnPassword(ctx, logID, logPrefix, scope.UserID) {
		return
	}

	h.deleteUser(ctx, logID, logPrefix, scope.UserID, "Failed to delete own user", "Deleted own user")
}

func (h *Handler) DeleteUserByID(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
	logPrefix := "[UserHandler][DeleteUserById]"

	id, err := gokit.ValidateUUIDParam(ctx, logID)
	if err != nil {
		return
	}
	scope := domainauth.FromContext(ctx.Request.Context())
	if id == scope.UserID {
		// Deleting yourself is the self-service route with its password check;
		// an impersonator can never delete the account it is acting as.
		if h.denyWhileImpersonating(ctx, logID, scope, "user", "delete the account") {
			return
		}
		if !h.confirmOwnPassword(ctx, logID, logPrefix, scope.UserID) {
			return
		}
	}
	h.deleteUser(ctx, logID, logPrefix, id, "Failed to delete user by ID", "Deleted user by ID")
}
