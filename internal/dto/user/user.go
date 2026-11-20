package user

import (
	"time"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

type Register struct {
	Name          string `json:"name" binding:"required,min=3,max=100"`
	Email         string `json:"email" binding:"required,email"`
	Phone         string `json:"phone" binding:"required,min=9,max=15"`
	Password      string `json:"password" binding:"required,min=8,max=64"`
	OTPCode       string `json:"otp_code" binding:"omitempty,len=6,numeric"`
	EmailVerified bool   `json:"-"`
}

type AdminCreateUser struct {
	Name     string `json:"name" binding:"required,min=3,max=100"`
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone" binding:"omitempty,min=9,max=15"`
	Password string `json:"password" binding:"required,min=8,max=64"`
	Role     string `json:"role" binding:"required"`
}

type Login struct {
	Identifier string `json:"identifier" binding:"omitempty,min=3,max=100"`
	Email      string `json:"email" binding:"omitempty,min=3,max=100"`
	Password   string `json:"password" binding:"required,max=72"`
}

type LoginMetadata struct {
	IP        string
	UserAgent string
}

type GoogleLogin struct {
	IDToken string `json:"id_token" binding:"required"`
}

type Update struct {
	Name  string `json:"name" binding:"omitempty,min=3,max=100"`
	Email string `json:"email" binding:"omitempty,email"`
	Phone string `json:"phone" binding:"omitempty,min=9,max=15"`
	Role  string `json:"role" binding:"omitempty"`
	// CurrentPassword is required when the caller changes their own email or phone.
	CurrentPassword string `json:"current_password" binding:"omitempty,max=72"`
}

type ChangePassword struct {
	CurrentPassword string `json:"current_password" binding:"required,min=8,max=64"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=64"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=64"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type SendRegisterOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
	Phone string `json:"phone" binding:"omitempty,min=9,max=15"`
}

type Impersonate struct {
	Reason string `json:"reason" binding:"required,min=3,max=500"`
}

// Logout is the optional request body of logout: the refresh token to revoke
// together with the access token.
type Logout struct {
	RefreshToken string `json:"refresh_token" binding:"omitempty"`
}

type DeleteOwn struct {
	CurrentPassword string `json:"current_password" binding:"required,max=72"`
}

// Response is the JSON shape of a user in API responses. Login bookkeeping and
// metadata are filled only for a superadmin caller.
type Response struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Email              string         `json:"email,omitempty"`
	Phone              string         `json:"phone,omitempty"`
	Role               string         `json:"role,omitempty"`
	RoleID             *string        `json:"role_id,omitempty"`
	EmailVerifiedAt    *time.Time     `json:"email_verified_at,omitempty"`
	PhoneVerifiedAt    *time.Time     `json:"phone_verified_at,omitempty"`
	LastLoginAt        *time.Time     `json:"last_login_at,omitempty"`
	LastLoginIP        string         `json:"last_login_ip,omitempty"`
	LastLoginUserAgent string         `json:"last_login_user_agent,omitempty"`
	PasswordChangedAt  *time.Time     `json:"password_changed_at,omitempty"`
	LoginProvider      string         `json:"login_provider,omitempty"`
	AvatarURL          string         `json:"avatar_url,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          *time.Time     `json:"updated_at,omitempty"`
}

// NewResponse maps a user to its response. detailed adds the login IP, user
// agent and metadata; pass true for a superadmin caller only.
func NewResponse(u domainuser.Users, detailed bool) Response {
	r := Response{
		ID: u.ID, Name: u.Name, Email: u.Email, Phone: u.Phone, Role: u.Role, RoleID: u.RoleID,
		EmailVerifiedAt: u.EmailVerifiedAt, PhoneVerifiedAt: u.PhoneVerifiedAt, LastLoginAt: u.LastLoginAt,
		PasswordChangedAt: u.PasswordChangedAt, LoginProvider: u.LoginProvider, AvatarURL: u.AvatarURL,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
	if detailed {
		r.LastLoginIP, r.LastLoginUserAgent, r.Metadata = u.LastLoginIP, u.LastLoginUserAgent, u.Metadata
	}
	return r
}

// NewResponses maps a page of users.
func NewResponses(users []domainuser.Users, detailed bool) []Response {
	out := make([]Response, 0, len(users))
	for _, u := range users {
		out = append(out, NewResponse(u, detailed))
	}
	return out
}
