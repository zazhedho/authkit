package user

// Register is the user request body for user register.
type Register struct {
	Name          string `json:"name" binding:"required,min=3,max=100"`
	Email         string `json:"email" binding:"required,email"`
	Phone         string `json:"phone" binding:"required,min=9,max=15"`
	Password      string `json:"password" binding:"required,min=8,max=64"`
	OTPCode       string `json:"otp_code" binding:"omitempty,len=6,numeric"`
	EmailVerified bool   `json:"-"`
}

// AdminCreateUser is the user request body for admin create user.
type AdminCreateUser struct {
	Name     string `json:"name" binding:"required,min=3,max=100"`
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone" binding:"omitempty,min=9,max=15"`
	Password string `json:"password" binding:"required,min=8,max=64"`
	Role     string `json:"role" binding:"required"`
}

// Login is the user request body for login.
type Login struct {
	Identifier string `json:"identifier" binding:"omitempty,min=3,max=100"`
	Email      string `json:"email" binding:"omitempty,min=3,max=100"`
	Password   string `json:"password" binding:"required,min=8,max=64"`
}

// LoginMetadata is the user request body for login metadata.
type LoginMetadata struct {
	IP        string
	UserAgent string
}

// GoogleLogin is the user request body for google login.
type GoogleLogin struct {
	IDToken string `json:"id_token" binding:"required"`
}

// Update is the user request body for user update.
type Update struct {
	Name  string `json:"name" binding:"omitempty,min=3,max=100"`
	Email string `json:"email" binding:"omitempty,email"`
	Phone string `json:"phone" binding:"omitempty,min=9,max=15"`
	Role  string `json:"role" binding:"omitempty"`
}

// ChangePassword is the user request body for change password.
type ChangePassword struct {
	CurrentPassword string `json:"current_password" binding:"required,min=8,max=64"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=64"`
}

// ForgotPasswordRequest is the user request body for forgot password request.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest is the user request body for reset password request.
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=64"`
}

// RefreshTokenRequest is the user request body for refresh token request.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// SendRegisterOTPRequest is the user request body for send register OTP request.
type SendRegisterOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
	Phone string `json:"phone" binding:"omitempty,min=9,max=15"`
}
