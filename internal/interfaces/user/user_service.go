package user

import (
	"context"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	"github.com/zazhedho/gokit"
)

type ServiceUserInterface interface {
	RegisterUser(ctx context.Context, req dtouser.UserRegister) (domainuser.Users, error)
	AdminCreateUser(ctx context.Context, req dtouser.AdminCreateUser) (domainuser.Users, error)
	LoginUser(ctx context.Context, req dtouser.Login, logId string, metadata dtouser.LoginMetadata) (string, error)
	LoginWithGoogle(ctx context.Context, req dtouser.GoogleLogin, metadata dtouser.LoginMetadata, allowRegistration bool) (domainuser.Users, bool, error)
	LogoutUser(ctx context.Context, token string) error
	ImpersonateUser(ctx context.Context, targetUserId string, logId string) (string, error)
	StopImpersonation(ctx context.Context, logId string) (string, error)
	GetUserById(ctx context.Context, id string) (domainuser.Users, error)
	GetUserByEmail(ctx context.Context, email string) (domainuser.Users, error)
	GetUserByPhone(ctx context.Context, phone string) (domainuser.Users, error)
	GetUserByAuth(ctx context.Context, id string) (map[string]any, error)
	GetAllUsers(ctx context.Context, params gokit.BaseParams) ([]domainuser.Users, int64, error)
	Update(ctx context.Context, id string, req dtouser.UserUpdate) (domainuser.Users, error)
	ChangePassword(ctx context.Context, id string, req dtouser.ChangePassword) (domainuser.Users, error)
	ForgotPassword(ctx context.Context, req dtouser.ForgotPasswordRequest) (string, error)
	ResetPassword(ctx context.Context, req dtouser.ResetPasswordRequest) error
	ResetPasswordByEmail(ctx context.Context, email, newPassword string) error
	Delete(ctx context.Context, id string) error
}
