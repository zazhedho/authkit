package user

import (
	"context"
	"regexp"

	"golang.org/x/crypto/bcrypt"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

var (
	reLower  = regexp.MustCompile(`[a-z]`)
	reUpper  = regexp.MustCompile(`[A-Z]`)
	reNumber = regexp.MustCompile(`[0-9]`)
	reSymbol = regexp.MustCompile(`[^a-zA-Z0-9]`)
)

// passwordCost is the bcrypt cost new hashes use; a login rehashes a hash made
// with a lower cost. Tests lower it to stay fast.
var passwordCost = 12

// maxPasswordBytes is bcrypt's input limit; longer input would be truncated.
const maxPasswordBytes = 72

// weakPasswordError keeps the readable message while matching ErrWeakPassword.
type weakPasswordError string

func (e weakPasswordError) Error() string        { return string(e) }
func (e weakPasswordError) Is(target error) bool { return target == domainuser.ErrWeakPassword }

// ValidatePasswordStrength checks length, character classes and bcrypt's limit.
func ValidatePasswordStrength(password string) error {
	if len(password) > maxPasswordBytes {
		return domainuser.ErrPasswordTooLong
	}
	switch {
	case len(password) < 8:
		return weakPasswordError("password must be at least 8 characters long")
	case !reLower.MatchString(password):
		return weakPasswordError("password must contain at least 1 lowercase letter (a-z)")
	case !reUpper.MatchString(password):
		return weakPasswordError("password must contain at least 1 uppercase letter (A-Z)")
	case !reNumber.MatchString(password):
		return weakPasswordError("password must contain at least 1 number (0-9)")
	case !reSymbol.MatchString(password):
		return weakPasswordError("password must contain at least 1 symbol (!@#$%^&*...)")
	}
	return nil
}

func hashPassword(password string) (string, error) {
	if len(password) > maxPasswordBytes {
		return "", domainuser.ErrPasswordTooLong
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), passwordCost)
	return string(h), err
}

// dummyHash is compared when no user matches, so a missing account costs the
// same as a wrong password.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("authkit-dummy-password"), passwordCost)

func buildUserAuthResponse(user domainuser.Users, permissions []string) map[string]any {
	if permissions == nil {
		permissions = []string{}
	}

	return map[string]any{
		"id":                  user.ID,
		"name":                user.Name,
		"email":               user.Email,
		"phone":               user.Phone,
		"role":                user.Role,
		"permissions":         permissions,
		"email_verified_at":   user.EmailVerifiedAt,
		"phone_verified_at":   user.PhoneVerifiedAt,
		"last_login_at":       user.LastLoginAt,
		"login_provider":      user.LoginProvider,
		"avatar_url":          user.AvatarURL,
		"password_changed_at": user.PasswordChangedAt,
		"created_at":          user.CreatedAt,
		"updated_at":          user.UpdatedAt,
	}
}

func findRoleIDByName(ctx context.Context, roleRepo RoleRepository, roleName string) (*string, bool) {
	roleEntity, err := roleRepo.GetByName(ctx, roleName)
	if err != nil || roleEntity.ID == "" {
		return nil, false
	}

	return &roleEntity.ID, true
}
