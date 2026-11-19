package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"

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

// RegisterUser registers the user.
func (s *Service) RegisterUser(ctx context.Context, req dtouser.Register) (domainuser.Users, error) {
	phone := domainuser.NormalizePhoneTo62(req.Phone)
	email := domainuser.SanitizeEmail(req.Email)

	data, _ := s.UserRepo.GetByEmail(ctx, email)
	if data.ID != "" {
		return domainuser.Users{}, errors.New("email already exists")
	}

	phoneData, _ := s.UserRepo.GetByPhone(ctx, phone)
	if phoneData.ID != "" {
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

	roleID, ok := findRoleIDByName(ctx, s.RoleRepo, roleName)
	if !ok {
		return domainuser.Users{}, fmt.Errorf("role %s is not configured", roleName)
	}
	var emailVerifiedAt *time.Time
	if req.EmailVerified {
		emailVerifiedAt = new(time.Now())
	}

	data = domainuser.Users{
		ID:                s.newID(),
		Name:              serviceshared.TitleCase(serviceshared.CleanText(req.Name)),
		Phone:             phone,
		Email:             email,
		Password:          string(hashedPwd),
		Role:              roleName,
		RoleID:            roleID,
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
	if data.ID != "" {
		return domainuser.Users{}, errors.New("email already exists")
	}

	if phone != "" {
		phoneData, _ := s.UserRepo.GetByPhone(ctx, phone)
		if phoneData.ID != "" {
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

	if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, roleName); err != nil {
		return domainuser.Users{}, err
	}

	roleID, ok := findRoleIDByName(ctx, s.RoleRepo, roleName)
	if !ok {
		return domainuser.Users{}, errors.New("invalid role: " + roleName)
	}

	data = domainuser.Users{
		ID:                s.newID(),
		Name:              serviceshared.TitleCase(serviceshared.CleanText(req.Name)),
		Phone:             phone,
		Email:             email,
		Password:          string(hashedPwd),
		Role:              roleName,
		RoleID:            roleID,
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

func (s *Service) LoginUser(ctx context.Context, req dtouser.Login, logID string, metadata dtouser.LoginMetadata) (string, error) {
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

	token, err := s.Tokens.Generate(data.ID, data.Name, data.Role, logID)
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

// ImpersonateUser issues a short-lived token for the target. The actor must
// cover the target's role and give a reason, which the handler audits.
func (s *Service) ImpersonateUser(ctx context.Context, actor domainauth.Actor, targetUserID, reason, logID string) (string, error) {
	if actor.IsImpersonated {
		return "", errors.New("cannot start nested impersonation")
	}
	if strings.TrimSpace(targetUserID) == "" {
		return "", errors.New("target user id is required")
	}
	if targetUserID == actor.UserID {
		return "", errors.New("cannot impersonate your own account")
	}
	if strings.TrimSpace(reason) == "" {
		return "", domainuser.ErrReasonRequired
	}

	targetUser, err := s.UserRepo.GetByID(ctx, targetUserID)
	if err != nil {
		return "", err
	}
	if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, targetUser.Role); err != nil {
		return "", err
	}

	return s.Tokens.GenerateImpersonated(targetUser.ID, targetUser.Name, targetUser.Role, logID, actor.UserID, actor.Username, actor.Role)
}

// StopImpersonation stops the impersonation.
func (s *Service) StopImpersonation(ctx context.Context, actor domainauth.Actor, logID string) (string, error) {
	originalUserID := actor.OriginalUserID
	currentUserID := actor.UserID

	if strings.TrimSpace(originalUserID) == "" {
		return "", errors.New("original user id is required")
	}
	if originalUserID == currentUserID {
		return "", errors.New("current session is not impersonated")
	}

	originalUser, err := s.UserRepo.GetByID(ctx, originalUserID)
	if err != nil {
		return "", err
	}

	return s.Tokens.Generate(originalUser.ID, originalUser.Name, originalUser.Role, logID)
}

func (s *Service) GetUserByID(ctx context.Context, id string) (domainuser.Users, error) {
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

	permissions, err := s.PermissionRepo.GetUserPermissions(ctx, user.ID)
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

func (s *Service) GetAllUsers(ctx context.Context, actor domainauth.Actor, req dtoshared.ListRequest) ([]domainuser.Users, int64, error) {
	users, total, err := s.UserRepo.GetAll(ctx, req)
	return serviceshared.HideSuperAdmin(actor, users, total, err, func(user domainuser.Users) bool {
		return user.Role == domainuser.RoleSuperAdmin
	})
}

// Update edits a user. The role rule applies to every target but the actor's
// own account; the actor's own role never changes through it.
func (s *Service) Update(ctx context.Context, actor domainauth.Actor, id string, req dtouser.Update) (domainuser.Users, error) {
	data, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return domainuser.Users{}, err
	}
	self := id == actor.UserID
	if !self {
		if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, data.Role); err != nil {
			return domainuser.Users{}, err
		}
	}

	var credentialsChanged bool
	if req.Name != "" {
		data.Name = serviceshared.TitleCase(serviceshared.CleanText(req.Name))
	}

	if req.Phone != "" {
		if phone := domainuser.NormalizePhoneTo62(req.Phone); phone != data.Phone {
			if err := s.requireOwnPassword(self, data, req.CurrentPassword); err != nil {
				return domainuser.Users{}, err
			}
			if err := s.ensurePhoneFree(ctx, id, phone); err != nil {
				return domainuser.Users{}, err
			}
			data.Phone = phone
			data.PhoneVerifiedAt = nil
		}
	}

	if req.Email != "" {
		email := domainuser.SanitizeEmail(req.Email)
		if email == "" {
			return domainuser.Users{}, domainuser.ErrEmailRequired
		}
		if email != data.Email {
			if err := s.requireOwnPassword(self, data, req.CurrentPassword); err != nil {
				return domainuser.Users{}, err
			}
			if err := s.ensureEmailFree(ctx, id, email); err != nil {
				return domainuser.Users{}, err
			}
			data.Email = email
			data.EmailVerifiedAt = nil
			credentialsChanged = true
		}
	}

	roleChanged, err := s.applyRoleUpdate(ctx, actor, req.Role, &data)
	if err != nil {
		return domainuser.Users{}, err
	}

	if err = s.UserRepo.Update(ctx, data); err != nil {
		return domainuser.Users{}, err
	}
	if roleChanged || credentialsChanged {
		if err := s.revokeTokens(ctx, id); err != nil {
			return domainuser.Users{}, err
		}
	}

	return data, nil
}

// requireOwnPassword makes a self-service change of a login identifier prove
// the current password. Admin edits go through the role rule instead.
func (s *Service) requireOwnPassword(self bool, user domainuser.Users, password string) error {
	if !self {
		return nil
	}
	if password == "" {
		return domainuser.ErrPasswordRequired
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		return domainuser.ErrPasswordIncorrect
	}
	return nil
}

func (s *Service) ensureEmailFree(ctx context.Context, id, email string) error {
	other, err := s.UserRepo.GetByEmail(ctx, email)
	if err != nil && !errors.Is(err, domainuser.ErrNotFound) {
		return err
	}
	if other.ID != "" && other.ID != id {
		return domainuser.ErrDuplicate
	}
	return nil
}

func (s *Service) ensurePhoneFree(ctx context.Context, id, phone string) error {
	other, err := s.UserRepo.GetByPhone(ctx, phone)
	if err != nil && !errors.Is(err, domainuser.ErrNotFound) {
		return err
	}
	if other.ID != "" && other.ID != id {
		return domainuser.ErrDuplicate
	}
	return nil
}

// revokeTokens invalidates every token issued before now for the user and
// drops the cached auth state so Auth sees it on the next request.
func (s *Service) revokeTokens(ctx context.Context, id string) error {
	return s.revokeTokensAt(ctx, id, time.Time{})
}

// revokeTokensAt revokes every token issued before at; a zero at means now.
func (s *Service) revokeTokensAt(ctx context.Context, id string, at time.Time) error {
	if at.IsZero() {
		at = time.Now()
	}
	if err := s.UserRepo.UpdateFields(ctx, id, map[string]any{"tokens_valid_after": at}); err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
	}
	s.invalidateUserPermissionCache(ctx, id)
	return nil
}

func (s *Service) applyRoleUpdate(ctx context.Context, actor domainauth.Actor, requestedRole string, user *domainuser.Users) (bool, error) {
	newRoleName := serviceshared.NormalizeKey(strings.TrimSpace(requestedRole))
	if newRoleName == "" || newRoleName == user.Role {
		return false, nil
	}
	if user.ID == actor.UserID {
		return false, domainuser.ErrSelfRoleChange
	}
	canAssignRole, err := serviceshared.HasPermission(ctx, s.PermissionRepo, actor, "users", "assign_role")
	if err != nil {
		return false, err
	}
	if !canAssignRole {
		return false, errors.New("access denied: missing permission users:assign_role")
	}
	if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, newRoleName); err != nil {
		return false, err
	}
	if user.Role == domainuser.RoleSuperAdmin {
		if err := s.ensureNotLastSuperAdmin(ctx); err != nil {
			return false, err
		}
	}
	roleID, ok := findRoleIDByName(ctx, s.RoleRepo, newRoleName)
	if !ok {
		return false, errors.New("invalid role: " + newRoleName)
	}
	user.Role = newRoleName
	user.RoleID = roleID
	return true, nil
}

func (s *Service) ensureNotLastSuperAdmin(ctx context.Context) error {
	n, err := s.UserRepo.CountByRole(ctx, domainuser.RoleSuperAdmin)
	if err != nil {
		return err
	}
	if n <= 1 {
		return domainuser.ErrLastSuperAdmin
	}
	return nil
}

// ChangePassword changes the password and revokes the user's tokens issued
// before keepFrom, so the caller's own session (issued at keepFrom) survives
// while older ones do not. A zero keepFrom revokes everything issued so far.
func (s *Service) ChangePassword(ctx context.Context, id string, req dtouser.ChangePassword, keepFrom time.Time) (domainuser.Users, error) {
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
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return domainuser.Users{}, domainuser.ErrPasswordIncorrect
		}
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
	if err = s.revokeTokensAt(ctx, id, keepFrom); err != nil {
		return domainuser.Users{}, err
	}

	return data, nil
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
	return s.revokeTokens(ctx, data.ID)
}

// Delete removes a user and revokes their tokens. The role rule applies to
// every target but the actor's own account, and the last superadmin stays.
func (s *Service) Delete(ctx context.Context, actor domainauth.Actor, id string) error {
	target, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if id != actor.UserID {
		if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, target.Role); err != nil {
			return err
		}
	}
	if target.Role == domainuser.RoleSuperAdmin {
		if err := s.ensureNotLastSuperAdmin(ctx); err != nil {
			return err
		}
	}
	// Bump first: a soft-deleted row no longer accepts updates.
	if err := s.revokeTokens(ctx, id); err != nil {
		return err
	}
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

// VerifyPassword checks a user's current password. A wrong one is
// domainuser.ErrPasswordIncorrect.
func (s *Service) VerifyPassword(ctx context.Context, id, password string) error {
	if password == "" {
		return domainuser.ErrPasswordRequired
	}
	user, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return domainuser.ErrPasswordIncorrect
		}
		return err
	}
	return nil
}
