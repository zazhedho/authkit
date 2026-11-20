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

	"github.com/zazhedho/logus"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	UserRepo        Repository
	BlacklistRepo   TokenRevocations
	RoleRepo        RoleRepository
	PermissionRepo  PermissionRepository
	PermissionCache PermissionCache
	// sessions, set through Options only, ends a user's sessions after their
	// credentials change.
	sessions SessionRevoker
	Tokens   TokenIssuer
	// DefaultRole is the role given to public registrations; empty means viewer.
	DefaultRole     string
	GoogleClientIDs []string
	// GoogleVerifier checks Google ID tokens; the root package injects it.
	GoogleVerifier GoogleVerifier
	// PhoneLogin lets a user sign in with a phone number. Phone numbers are
	// not verified, so it is off by default.
	PhoneLogin bool
	// NewID makes record ids; nil uses a UUID v7.
	NewID func() string
}

// Options carries the explicit configuration of Service.
type Options struct {
	Tokens          TokenIssuer
	DefaultRole     string
	GoogleClientIDs []string
	GoogleVerifier  GoogleVerifier
	PhoneLogin      bool
	PermissionCache PermissionCache
	Sessions        SessionRevoker
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
		sessions:        opts.Sessions,
		Tokens:          opts.Tokens,
		DefaultRole:     opts.DefaultRole,
		GoogleClientIDs: opts.GoogleClientIDs,
		GoogleVerifier:  opts.GoogleVerifier,
		PhoneLogin:      opts.PhoneLogin,
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

	if email == "" {
		return domainuser.Users{}, domainuser.ErrEmailRequired
	}
	if err := ValidatePasswordStrength(req.Password); err != nil {
		return domainuser.Users{}, err
	}
	// Hashing comes before the duplicate check so a taken address costs the
	// same time as a free one.
	hashedPwd, err := hashPassword(req.Password)
	if err != nil {
		return domainuser.Users{}, err
	}
	if err := s.ensureIdentifiersFree(ctx, email, phone); err != nil {
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

	data := domainuser.Users{
		ID:                s.newID(),
		Name:              serviceshared.TitleCase(serviceshared.CleanText(req.Name)),
		Phone:             phone,
		Email:             email,
		Password:          hashedPwd,
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

	if email == "" {
		return domainuser.Users{}, domainuser.ErrEmailRequired
	}
	if err := ValidatePasswordStrength(req.Password); err != nil {
		return domainuser.Users{}, err
	}
	hashedPwd, err := hashPassword(req.Password)
	if err != nil {
		return domainuser.Users{}, err
	}
	if err := s.ensureIdentifiersFree(ctx, email, phone); err != nil {
		return domainuser.Users{}, err
	}

	roleName := serviceshared.NormalizeKey(req.Role)
	canAssignRole, err := serviceshared.HasPermission(ctx, s.PermissionRepo, actor, "users", "assign_role")
	if err != nil {
		return domainuser.Users{}, err
	}

	if roleName != s.defaultRole() && !canAssignRole {
		return domainuser.Users{}, fmt.Errorf("%w: missing permission users:assign_role", domainuser.ErrAccessDenied)
	}

	if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, roleName); err != nil {
		return domainuser.Users{}, err
	}

	roleID, ok := findRoleIDByName(ctx, s.RoleRepo, roleName)
	if !ok {
		return domainuser.Users{}, fmt.Errorf("%w: %s", domainuser.ErrInvalidRole, roleName)
	}

	data := domainuser.Users{
		ID:                s.newID(),
		Name:              serviceshared.TitleCase(serviceshared.CleanText(req.Name)),
		Phone:             phone,
		Email:             email,
		Password:          hashedPwd,
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

func (s *Service) LoginUser(ctx context.Context, req dtouser.Login, metadata dtouser.LoginMetadata) (string, error) {
	identifier, err := domainuser.ResolveLoginIdentifier(req.Identifier, req.Email)
	if err != nil {
		return "", err
	}

	var (
		data     domainuser.Users
		loginErr error
	)
	switch {
	case strings.Contains(identifier, "@"):
		data, loginErr = s.UserRepo.GetByEmail(ctx, identifier)
	case s.PhoneLogin:
		data, loginErr = s.UserRepo.GetByPhone(ctx, identifier)
	default:
		loginErr = domainuser.ErrNotFound
	}
	if loginErr != nil && !errors.Is(loginErr, domainuser.ErrNotFound) {
		return "", loginErr
	}
	if loginErr != nil {
		// Spend the same time as a wrong password.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		return "", domainuser.ErrInvalidCredentials
	}

	if err = bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(req.Password)); err != nil {
		return "", domainuser.ErrInvalidCredentials
	}

	fields := map[string]any{
		"last_login_at":         time.Now(),
		"last_login_ip":         metadata.IP,
		"last_login_user_agent": metadata.UserAgent,
	}
	if data.LoginProvider == "" {
		fields["login_provider"] = "local"
	}
	if cost, costErr := bcrypt.Cost([]byte(data.Password)); costErr == nil && cost < passwordCost {
		if rehashed, hashErr := hashPassword(req.Password); hashErr == nil {
			fields["password"] = rehashed
		}
	}
	if err = s.UserRepo.UpdateFields(ctx, data.ID, fields); err != nil {
		return "", err
	}

	return s.Tokens.Generate(data.ID, data.Name, data.Role, derefTime(data.TokensValidAfter))
}

// ensureIdentifiersFree returns ErrDuplicate when the email or phone belongs
// to a live user, without saying which; a failed lookup is returned as is.
func (s *Service) ensureIdentifiersFree(ctx context.Context, email, phone string) error {
	existing, err := s.UserRepo.GetByEmail(ctx, email)
	if err != nil && !errors.Is(err, domainuser.ErrNotFound) {
		return err
	}
	if err == nil && existing.ID != "" {
		return domainuser.ErrDuplicate
	}
	if phone == "" {
		return nil
	}
	existing, err = s.UserRepo.GetByPhone(ctx, phone)
	if err != nil && !errors.Is(err, domainuser.ErrNotFound) {
		return err
	}
	if err == nil && existing.ID != "" {
		return domainuser.ErrDuplicate
	}
	return nil
}

// blacklistGrace keeps a revoked token's row past its exp, so a purge can never
// run before the last node that might still accept the token has seen it expire.
const blacklistGrace = 30 * time.Second

func (s *Service) LogoutUser(ctx context.Context, token string) error {
	expiresAt, err := s.Tokens.ExpiresAt(token)
	if err != nil {
		return err
	}

	blacklist := domainauth.Blacklist{
		ID:        s.newID(),
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt.Add(blacklistGrace),
	}

	err = s.BlacklistRepo.Store(ctx, blacklist)
	if err != nil {
		return err
	}

	return nil
}

// ImpersonateUser needs both accounts live and a covered target role; the token
// is issued after both accounts' latest revocation.
func (s *Service) ImpersonateUser(ctx context.Context, actor domainauth.Actor, targetUserID, reason string, bind domainuser.ActorBinding) (string, error) {
	if actor.IsImpersonated {
		return "", domainuser.ErrNestedImpersonation
	}
	if strings.TrimSpace(targetUserID) == "" {
		return "", domainuser.ErrTargetRequired
	}
	if targetUserID == actor.UserID {
		return "", domainuser.ErrSelfImpersonation
	}
	if strings.TrimSpace(reason) == "" {
		return "", domainuser.ErrReasonRequired
	}

	actorUser, err := s.UserRepo.GetByID(ctx, actor.UserID)
	if errors.Is(err, domainuser.ErrNotFound) {
		return "", domainuser.ErrImpersonatorRevoked
	}
	if err != nil {
		return "", err
	}
	targetUser, err := s.UserRepo.GetByID(ctx, targetUserID)
	if err != nil {
		return "", err
	}
	if err := hideSuperAdmin(actor, targetUser); err != nil {
		return "", err
	}
	if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, targetUser.Role); err != nil {
		return "", err
	}

	after := laterOf(derefTime(actorUser.TokensValidAfter), derefTime(targetUser.TokensValidAfter))
	return s.Tokens.GenerateImpersonatedBound(targetUser.ID, targetUser.Name, targetUser.Role, dtoshared.ImpersonationClaims{
		OriginalUserID:   actor.UserID,
		OriginalUsername: actor.Username,
		OriginalRole:     actor.Role,
		ActorSessionID:   bind.SessionID,
		ActorTokenHash:   bind.TokenHash,
	}, after)
}

// StopImpersonation needs the original account live and unrevoked since the
// impersonation token was issued. The restored token is no_session: it ends with
// tokens_valid_after or its TTL, not with a session being revoked.
func (s *Service) StopImpersonation(ctx context.Context, actor domainauth.Actor, issuedAtMS int64) (string, error) {
	originalUserID := actor.OriginalUserID
	if strings.TrimSpace(originalUserID) == "" {
		return "", domainuser.ErrOriginalRequired
	}
	if originalUserID == actor.UserID {
		return "", domainuser.ErrNotImpersonated
	}

	originalUser, err := s.UserRepo.GetByID(ctx, originalUserID)
	if errors.Is(err, domainuser.ErrNotFound) {
		return "", domainuser.ErrImpersonatorRevoked
	}
	if err != nil {
		return "", err
	}
	if cutoff := originalUser.TokensValidAfter; cutoff != nil && issuedAtMS <= cutoff.UnixMilli() {
		return "", domainuser.ErrImpersonatorRevoked
	}

	return s.Tokens.GenerateNoSession(originalUser.ID, originalUser.Name, originalUser.Role, derefTime(originalUser.TokensValidAfter))
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
	if actor.Role == domainuser.RoleSuperAdmin {
		return s.UserRepo.GetAll(ctx, req)
	}
	// Superadmins are left out by the query itself, so the page size and the
	// total count agree.
	return s.UserRepo.GetAllExcludingRole(ctx, req, domainuser.RoleSuperAdmin)
}

// GetUserForActor returns one user as the actor may see it: a superadmin
// account does not exist for anyone else.
func (s *Service) GetUserForActor(ctx context.Context, actor domainauth.Actor, id string) (domainuser.Users, error) {
	user, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return domainuser.Users{}, err
	}
	if user.Role == domainuser.RoleSuperAdmin && actor.Role != domainuser.RoleSuperAdmin {
		return domainuser.Users{}, domainuser.ErrNotFound
	}
	return user, nil
}

// Update applies the role rule to every target but the actor's own account. A
// role, email or (with PhoneLogin) phone change voids tokens in the same write
// and ends the sessions.
func (s *Service) Update(ctx context.Context, actor domainauth.Actor, id string, req dtouser.Update) (domainuser.Users, error) {
	data, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return domainuser.Users{}, err
	}
	if err := hideSuperAdmin(actor, data); err != nil {
		return domainuser.Users{}, err
	}
	self := id == actor.UserID
	if !self {
		if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, data.Role); err != nil {
			return domainuser.Users{}, err
		}
	}

	fields := map[string]any{}
	revoke := false
	if req.Name != "" {
		data.Name = serviceshared.TitleCase(serviceshared.CleanText(req.Name))
		fields["name"] = data.Name
	}

	if req.Phone != "" {
		if phone := domainuser.NormalizePhoneTo62(req.Phone); phone != data.Phone {
			if err := s.requireOwnPassword(self, data, req.CurrentPassword); err != nil {
				return domainuser.Users{}, err
			}
			if err := s.ensurePhoneFree(ctx, id, phone); err != nil {
				return domainuser.Users{}, err
			}
			data.Phone, data.PhoneVerifiedAt = phone, nil
			fields["phone"], fields["phone_verified_at"] = phone, nil
			revoke = revoke || s.PhoneLogin
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
			data.Email, data.EmailVerifiedAt = email, nil
			fields["email"], fields["email_verified_at"] = email, nil
			revoke = true
		}
	}

	roleChanged, err := s.applyRoleUpdate(ctx, actor, req.Role, &data)
	if err != nil {
		return domainuser.Users{}, err
	}
	if roleChanged {
		fields["role"], fields["role_id"] = data.Role, *data.RoleID
		revoke = true
	}

	if len(fields) == 0 {
		return data, nil
	}
	data.UpdatedAt = new(time.Now())
	if revoke {
		cutoff, err := s.UserRepo.UpdateFieldsRevoking(ctx, id, fields)
		if err != nil {
			return domainuser.Users{}, err
		}
		data.TokensValidAfter = &cutoff
		if err := s.afterRevocation(ctx, id); err != nil {
			return domainuser.Users{}, err
		}
		return data, nil
	}
	if err := s.UserRepo.UpdateFields(ctx, id, fields); err != nil {
		return domainuser.Users{}, err
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

// afterRevocation runs once tokens_valid_after is written: it drops the cached
// auth state, so Auth sees the cut-off on the next request, and ends the
// user's sessions.
func (s *Service) afterRevocation(ctx context.Context, id string) error {
	s.invalidateUserPermissionCache(ctx, id)
	if s.sessions == nil {
		return nil
	}
	if err := s.sessions.DestroyAllUserSessions(ctx, id); err != nil {
		return fmt.Errorf("%w: %w", domainuser.ErrSessionRevocation, err)
	}
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
		return false, fmt.Errorf("%w: missing permission users:assign_role", domainuser.ErrAccessDenied)
	}
	if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, newRoleName); err != nil {
		return false, err
	}
	roleID, ok := findRoleIDByName(ctx, s.RoleRepo, newRoleName)
	if !ok {
		return false, fmt.Errorf("%w: %s", domainuser.ErrInvalidRole, newRoleName)
	}
	user.Role = newRoleName
	user.RoleID = roleID
	return true, nil
}

// ChangePassword writes the hash and the token cut-off in one statement and
// returns the cut-off, so the caller issues its new tokens after it.
func (s *Service) ChangePassword(ctx context.Context, id string, req dtouser.ChangePassword) (time.Time, error) {
	if req.CurrentPassword == req.NewPassword {
		return time.Time{}, domainuser.ErrSamePassword
	}
	if err := ValidatePasswordStrength(req.NewPassword); err != nil {
		return time.Time{}, err
	}

	data, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return time.Time{}, err
	}
	if err = bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(req.CurrentPassword)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return time.Time{}, domainuser.ErrPasswordIncorrect
		}
		return time.Time{}, err
	}

	hashedPwd, err := hashPassword(req.NewPassword)
	if err != nil {
		return time.Time{}, err
	}
	cutoff, err := s.UserRepo.UpdateFieldsRevoking(ctx, id, map[string]any{
		"password": hashedPwd, "password_changed_at": time.Now(),
	})
	if err != nil {
		return time.Time{}, err
	}
	s.invalidateUserPermissionCache(ctx, id)
	return cutoff, nil
}

// ResetPasswordByEmail sets a new password for the account with that e-mail,
// voids its tokens in the same write and ends its sessions.
func (s *Service) ResetPasswordByEmail(ctx context.Context, email, newPassword string) error {
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	data, err := s.UserRepo.GetByEmail(ctx, domainuser.SanitizeEmail(email))
	if err != nil {
		return err
	}
	hashedPwd, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	if _, err = s.UserRepo.UpdateFieldsRevoking(ctx, data.ID, map[string]any{
		"password": hashedPwd, "password_changed_at": time.Now(),
	}); err != nil {
		return err
	}
	return s.afterRevocation(ctx, data.ID)
}

// Delete removes a user. The role rule applies to every target but the actor's
// own account, and the last superadmin stays (the repository enforces it under
// a row lock). A deleted user fails Auth at once; sessions are ended too.
func (s *Service) Delete(ctx context.Context, actor domainauth.Actor, id string) error {
	target, err := s.UserRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := hideSuperAdmin(actor, target); err != nil {
		return err
	}
	if id != actor.UserID {
		if err := serviceshared.CheckRoleCoverage(ctx, s.PermissionRepo, actor, target.Role); err != nil {
			return err
		}
	}
	if err := s.UserRepo.Delete(ctx, id); err != nil {
		return err
	}
	if err := s.afterRevocation(ctx, id); err != nil {
		// The account is gone and Auth rejects it; leftover sessions expire.
		logus.Logf(logus.LevelError, "user service: delete %s: %v", id, err)
	}
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

// ValidatePassword checks a new password against the strength rules and
// bcrypt's length limit without storing anything.
func (s *Service) ValidatePassword(password string) error { return ValidatePasswordStrength(password) }

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// hideSuperAdmin answers ErrNotFound (404) for a superadmin target to anyone
// else, like the read routes, so the account is not revealed by a 403.
func hideSuperAdmin(actor domainauth.Actor, target domainuser.Users) error {
	if target.Role == domainuser.RoleSuperAdmin && actor.Role != domainuser.RoleSuperAdmin {
		return domainuser.ErrNotFound
	}
	return nil
}
