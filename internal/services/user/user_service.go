package user

import (
	"context"
	"errors"
	"fmt"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	UserRepo        Repository
	BlacklistRepo   TokenRevocations
	RoleRepo        RoleRepository
	PermissionRepo  PermissionRepository
	PermissionCache PermissionCache
	Tokens          TokenIssuer
	// DefaultRole is the role given to public registrations; empty means viewer.
	DefaultRole     string
	GoogleClientIDs []string
	// NewID makes record ids; nil uses a UUID v7.
	NewID func() string
}

// Options carries the explicit configuration of Service.
type Options struct {
	Tokens          TokenIssuer
	DefaultRole     string
	GoogleClientIDs []string
	PermissionCache PermissionCache
	// NewID makes record ids; nil uses a UUID v7.
	NewID func() string
}

func NewService(userRepo Repository, blacklistRepo TokenRevocations, roleRepo RoleRepository, permissionRepo PermissionRepository, opts Options) *Service {
	return &Service{
		UserRepo:        userRepo,
		BlacklistRepo:   blacklistRepo,
		RoleRepo:        roleRepo,
		PermissionRepo:  permissionRepo,
		PermissionCache: opts.PermissionCache,
		Tokens:          opts.Tokens,
		DefaultRole:     opts.DefaultRole,
		GoogleClientIDs: opts.GoogleClientIDs,
		NewID:           opts.NewID,
	}
}

func (s *Service) newID() string {
	if s.NewID != nil {
		return s.NewID()
	}
	return serviceshared.NewID()
}

// defaultRole is the role for public registrations; privileged roles fall back
// to viewer so misconfiguration cannot escalate privileges.
func (s *Service) defaultRole() string {
	role := serviceshared.NormalizeKey(s.DefaultRole)
	if role == "" || role == domainuser.RoleSuperAdmin || role == domainuser.RoleAdmin {
		return domainuser.RoleViewer
	}
	return role
}

func (s *Service) RegisterUser(ctx context.Context, req dtouser.UserRegister) (domainuser.Users, error) {
	phone := domainuser.NormalizePhoneTo62(req.Phone)
	email := domainuser.SanitizeEmail(req.Email)

	data, _ := s.UserRepo.GetByEmail(ctx, email)
	if data.Id != "" {
		return domainuser.Users{}, errors.New("email already exists")
	}

	phoneData, _ := s.UserRepo.GetByPhone(ctx, phone)
	if phoneData.Id != "" {
		return domainuser.Users{}, errors.New("phone number already exists")
	}

	if err := ValidatePasswordStrength(req.Password); err != nil {
		return domainuser.Users{}, err
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return domainuser.Users{}, err
	}

	// Public registration never takes its role from the request, which would
	// allow privilege escalation.
	roleName := s.defaultRole()

	roleId, ok := findRoleIDByName(ctx, s.RoleRepo, roleName)
	if !ok {
		return domainuser.Users{}, fmt.Errorf("role %s is not configured", roleName)
	}
	var emailVerifiedAt *time.Time
	if req.EmailVerified {
		emailVerifiedAt = new(time.Now())
	}

	data = domainuser.Users{
		Id:                s.newID(),
		Name:              serviceshared.TitleCase(serviceshared.StripHTML(req.Name)),
		Phone:             phone,
		Email:             email,
		Password:          string(hashedPwd),
		Role:              roleName,
		RoleId:            roleId,
		EmailVerifiedAt:   emailVerifiedAt,
		PasswordChangedAt: new(time.Now()),
		LoginProvider:     "local",
		Metadata:          map[string]any{},
		CreatedAt:         time.Now(),
	}

	if err = s.UserRepo.Store(ctx, data); err != nil {
		return domainuser.Users{}, err
	}

	return data, nil
}

func (s *Service) AdminCreateUser(ctx context.Context, actor domainauth.Actor, req dtouser.AdminCreateUser) (domainuser.Users, error) {
	phone := domainuser.NormalizePhoneTo62(req.Phone)
	email := domainuser.SanitizeEmail(req.Email)

	data, _ := s.UserRepo.GetByEmail(ctx, email)
	if data.Id != "" {
		return domainuser.Users{}, errors.New("email already exists")
	}

	if phone != "" {
		phoneData, _ := s.UserRepo.GetByPhone(ctx, phone)
		if phoneData.Id != "" {
			return domainuser.Users{}, errors.New("phone number already exists")
		}
	}

	if err := ValidatePasswordStrength(req.Password); err != nil {
		return domainuser.Users{}, err
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return domainuser.Users{}, err
	}

	roleName := serviceshared.NormalizeKey(req.Role)
	canAssignRole, err := serviceshared.HasPermission(ctx, s.PermissionRepo, actor, "users", "assign_role")
	if err != nil {
		return domainuser.Users{}, err
	}

	if roleName != s.defaultRole() && !canAssignRole {
		return domainuser.Users{}, errors.New("access denied: missing permission users:assign_role")
	}

	if roleName == domainuser.RoleSuperAdmin && actor.Role != domainuser.RoleSuperAdmin {
		return domainuser.Users{}, errors.New("only superadmin can create superadmin users")
	}

	roleId, ok := findRoleIDByName(ctx, s.RoleRepo, roleName)
	if !ok {
		return domainuser.Users{}, errors.New("invalid role: " + roleName)
	}

	data = domainuser.Users{
		Id:                s.newID(),
		Name:              serviceshared.TitleCase(serviceshared.StripHTML(req.Name)),
		Phone:             phone,
		Email:             email,
		Password:          string(hashedPwd),
		Role:              roleName,
		RoleId:            roleId,
		PasswordChangedAt: new(time.Now()),
		LoginProvider:     "local",
		Metadata:          map[string]any{},
		CreatedAt:         time.Now(),
	}

	if err = s.UserRepo.Store(ctx, data); err != nil {
		return domainuser.Users{}, err
	}

	return data, nil
}

func (s *Service) LoginUser(ctx context.Context, req dtouser.Login, logId string, metadata dtouser.LoginMetadata) (string, error) {
	identifier, err := domainuser.ResolveLoginIdentifier(req.Identifier, req.Email)
	if err != nil {
		return "", err
	}

	var (
		data     domainuser.Users
		loginErr error
	)
	if strings.Contains(identifier, "@") {
		data, loginErr = s.UserRepo.GetByEmail(ctx, identifier)
	} else {
		data, loginErr = s.UserRepo.GetByPhone(ctx, identifier)
	}
	if loginErr != nil {
		return "", loginErr
	}

	if err = bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(req.Password)); err != nil {
		return "", err
	}

	data.LastLoginAt = new(time.Now())
	data.LastLoginIP = metadata.IP
	data.LastLoginUserAgent = metadata.UserAgent
	if data.LoginProvider == "" {
		data.LoginProvider = "local"
	}
	if err = s.UserRepo.Update(ctx, data); err != nil {
		return "", err
	}

	token, err := s.Tokens.Generate(&data, logId)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *Service) LogoutUser(ctx context.Context, token string) error {
	expiresAt, err := s.Tokens.ExpiresAt(token)
	if err != nil {
		return err
	}

	blacklist := domainauth.Blacklist{
		ID:        s.newID(),
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	err = s.BlacklistRepo.Store(ctx, blacklist)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) ImpersonateUser(ctx context.Context, actor domainauth.Actor, targetUserId string, logId string) (string, error) {
	if actor.IsImpersonated {
		return "", errors.New("cannot start nested impersonation")
	}
	if strings.TrimSpace(targetUserId) == "" {
		return "", errors.New("target user id is required")
	}
	if targetUserId == actor.UserID {
		return "", errors.New("cannot impersonate your own account")
	}

	targetUser, err := s.UserRepo.GetByID(ctx, targetUserId)
	if err != nil {
		return "", err
	}

	if targetUser.Role == domainuser.RoleSuperAdmin && actor.Role != domainuser.RoleSuperAdmin {
		return "", errors.New("cannot impersonate superadmin users")
	}

	return s.Tokens.GenerateImpersonated(&targetUser, logId, actor.UserID, actor.Username, actor.Role)
}

func (s *Service) StopImpersonation(ctx context.Context, actor domainauth.Actor, logId string) (string, error) {
	originalUserId := actor.OriginalUserID
	currentUserId := actor.UserID

	if strings.TrimSpace(originalUserId) == "" {
		return "", errors.New("original user id is required")
	}
	if originalUserId == currentUserId {
		return "", errors.New("current session is not impersonated")
	}

	originalUser, err := s.UserRepo.GetByID(ctx, originalUserId)
	if err != nil {
		return "", err
	}

	return s.Tokens.Generate(&originalUser, logId)
}

func (s *Service) GetUserById(ctx context.Context, id string) (domainuser.Users, error) {
	return s.UserRepo.GetByID(ctx, id)
}

func (s *Service) GetUserByEmail(ctx context.Context, email string) (domainuser.Users, error) {
	return s.UserRepo.GetByEmail(ctx, email)
}

func (s *Service) GetUserByPhone(ctx context.Context, phone string) (domainuser.Users, error) {
	return s.UserRepo.GetByPhone(ctx, phone)
}

func (s *Service) GetUserByAuth(ctx context.Context, id string) (map[string]any, error) {
	user, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	permissions, err := s.PermissionRepo.GetUserPermissions(ctx, user.Id)
	if err != nil {
		//nolint:nilerr // Keep auth response available even if permission enrichment fails.
		return buildUserAuthResponse(user, nil), nil
	}

	permissionNames := make([]string, 0, len(permissions))
	for _, perm := range permissions {
		permissionNames = append(permissionNames, perm.Name)
	}

	return buildUserAuthResponse(user, permissionNames), nil
}

func (s *Service) GetAllUsers(ctx context.Context, actor domainauth.Actor, req dtouser.ListRequest) ([]domainuser.Users, int64, error) {
	users, total, err := s.UserRepo.GetAll(ctx, req)
	if err != nil {
		return nil, 0, err
	}

	if actor.Role != domainuser.RoleSuperAdmin {
		filteredUsers := make([]domainuser.Users, 0)
		for _, user := range users {
			if user.Role != domainuser.RoleSuperAdmin {
				filteredUsers = append(filteredUsers, user)
			}
		}
		superadminCount := int64(len(users) - len(filteredUsers))
		return filteredUsers, total - superadminCount, nil
	}

	return users, total, nil
}

func (s *Service) Update(ctx context.Context, actor domainauth.Actor, id string, req dtouser.UserUpdate) (domainuser.Users, error) {
	data, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return domainuser.Users{}, err
	}

	if data.Role == domainuser.RoleSuperAdmin && actor.Role != domainuser.RoleSuperAdmin {
		return domainuser.Users{}, errors.New("cannot modify superadmin users")
	}

	if req.Name != "" {
		data.Name = serviceshared.TitleCase(serviceshared.StripHTML(req.Name))
	}

	if req.Phone != "" {
		phone := domainuser.NormalizePhoneTo62(req.Phone)
		data.Phone = phone
	}

	if req.Email != "" {
		data.Email = domainuser.SanitizeEmail(req.Email)
	}

	if err := s.applyRoleUpdate(ctx, actor, req.Role, &data); err != nil {
		return domainuser.Users{}, err
	}

	if err = s.UserRepo.Update(ctx, data); err != nil {
		return domainuser.Users{}, err
	}
	if strings.TrimSpace(req.Role) != "" {
		s.invalidateUserPermissionCache(ctx, id)
	}

	return data, nil
}

func (s *Service) applyRoleUpdate(ctx context.Context, actor domainauth.Actor, requestedRole string, user *domainuser.Users) error {
	newRoleName := serviceshared.NormalizeKey(strings.TrimSpace(requestedRole))
	if newRoleName == "" {
		return nil
	}
	canAssignRole, err := serviceshared.HasPermission(ctx, s.PermissionRepo, actor, "users", "assign_role")
	if err != nil {
		return err
	}
	if !canAssignRole {
		return errors.New("access denied: missing permission users:assign_role")
	}
	if newRoleName == domainuser.RoleSuperAdmin && actor.Role != domainuser.RoleSuperAdmin {
		return errors.New("cannot assign superadmin role")
	}
	roleID, ok := findRoleIDByName(ctx, s.RoleRepo, newRoleName)
	if !ok {
		return errors.New("invalid role: " + newRoleName)
	}
	user.Role = newRoleName
	user.RoleId = roleID
	return nil
}

func (s *Service) ChangePassword(ctx context.Context, id string, req dtouser.ChangePassword) (domainuser.Users, error) {
	if req.CurrentPassword == req.NewPassword {
		return domainuser.Users{}, errors.New("new password must be different from current password")
	}

	if err := ValidatePasswordStrength(req.NewPassword); err != nil {
		return domainuser.Users{}, err
	}

	data, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return domainuser.Users{}, err
	}

	if err = bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(req.CurrentPassword)); err != nil {
		return domainuser.Users{}, err
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return domainuser.Users{}, err
	}

	data.Password = string(hashedPwd)
	data.PasswordChangedAt = new(time.Now())

	if err = s.UserRepo.Update(ctx, data); err != nil {
		return domainuser.Users{}, err
	}

	return data, nil
}

func (s *Service) ForgotPassword(ctx context.Context, req dtouser.ForgotPasswordRequest) (string, error) {
	data, err := s.UserRepo.GetByEmail(ctx, domainuser.SanitizeEmail(req.Email))
	if err != nil {
		//nolint:nilerr // Avoid disclosing whether an email is registered.
		return "", nil
	}

	token, err := s.Tokens.GeneratePasswordReset(&data, "reset_password")
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *Service) ResetPassword(ctx context.Context, req dtouser.ResetPasswordRequest) error {
	if err := ValidatePasswordStrength(req.NewPassword); err != nil {
		return err
	}

	claims, err := s.Tokens.Claims(req.Token)
	if err != nil {
		return errors.New("invalid or expired token")
	}
	if !s.Tokens.IsPasswordResetClaims(claims) {
		return errors.New("invalid or expired token")
	}

	isUsed, err := s.BlacklistRepo.ExistsByToken(ctx, req.Token)
	if err != nil {
		return err
	}
	if isUsed {
		return errors.New("invalid or expired token")
	}

	userId := strings.TrimSpace(serviceshared.InterfaceString(claims["user_id"]))
	if userId == "" {
		return errors.New("invalid or expired token")
	}

	data, err := s.UserRepo.GetByID(ctx, userId)
	if err != nil {
		return errors.New("user not found")
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	data.Password = string(hashedPwd)
	data.PasswordChangedAt = new(time.Now())

	if err = s.LogoutUser(ctx, req.Token); err != nil {
		return err
	}

	if err = s.UserRepo.Update(ctx, data); err != nil {
		return err
	}

	return nil
}

func (s *Service) ResetPasswordByEmail(ctx context.Context, email, newPassword string) error {
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	data, err := s.UserRepo.GetByEmail(ctx, domainuser.SanitizeEmail(email))
	if err != nil {
		return errors.New("user not found")
	}

	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	data.Password = string(hashedPwd)
	data.PasswordChangedAt = new(time.Now())

	if err = s.UserRepo.Update(ctx, data); err != nil {
		return err
	}

	return nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.UserRepo.Delete(ctx, id); err != nil {
		return err
	}
	s.invalidateUserPermissionCache(ctx, id)
	return nil
}

func (s *Service) invalidateUserPermissionCache(ctx context.Context, userIDs ...string) {
	if s.PermissionCache != nil {
		s.PermissionCache.DeleteUser(ctx, userIDs...)
	}
}

// IsTokenRevoked reports whether an access token was revoked at logout.
func (s *Service) IsTokenRevoked(ctx context.Context, token string) (bool, error) {
	return s.BlacklistRepo.ExistsByToken(ctx, token)
}
