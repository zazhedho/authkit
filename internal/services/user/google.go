package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
)

// GoogleIdentity is what a verified Google ID token says about the account.
type GoogleIdentity struct {
	Audience      string
	Email         string
	EmailVerified string
	Name          string
	Picture       string
	Subject       string
}

type googleTokenInfo = GoogleIdentity

// GoogleVerifier checks an ID token against the allowed client ids. It returns
// domainuser.ErrGoogleTokenInvalid, ErrGoogleEmailMissing or
// ErrGoogleNotConfigured for the matching failures.
type GoogleVerifier func(ctx context.Context, idToken string, clientIDs []string) (GoogleIdentity, error)

// googleIDTokenVerifier is the default until the root package injects the real
// verifier; tests replace it.
var googleIDTokenVerifier GoogleVerifier = func(context.Context, string, []string) (GoogleIdentity, error) {
	return GoogleIdentity{}, domainuser.ErrGoogleNotConfigured
}

func (s *Service) googleVerifier() GoogleVerifier {
	if s.GoogleVerifier != nil {
		return s.GoogleVerifier
	}
	return googleIDTokenVerifier
}

func (s *Service) LoginWithGoogle(ctx context.Context, req dtouser.GoogleLogin, metadata dtouser.LoginMetadata, allowRegistration bool) (domainuser.Users, bool, error) {
	identity, err := s.googleVerifier()(ctx, req.IDToken, s.GoogleClientIDs)
	if err != nil {
		return domainuser.Users{}, false, err
	}
	subject := strings.TrimSpace(identity.Subject)
	if subject == "" {
		return domainuser.Users{}, false, domainuser.ErrGoogleTokenInvalid
	}

	// The subject identifies the Google account for good; the email can change.
	linked, err := s.UserRepo.GetByGoogleSubject(ctx, subject)
	if err != nil && !errors.Is(err, domainuser.ErrNotFound) {
		return domainuser.Users{}, false, err
	}
	if err == nil && linked.ID != "" {
		return s.finishGoogleLogin(ctx, linked, identity, metadata, nil)
	}

	email := domainuser.SanitizeEmail(identity.Email)
	if email == "" {
		return domainuser.Users{}, false, domainuser.ErrGoogleEmailMissing
	}

	existing, err := s.UserRepo.GetByEmail(ctx, email)
	if err != nil && !errors.Is(err, domainuser.ErrNotFound) {
		return domainuser.Users{}, false, err
	}
	if err == nil && existing.ID != "" {
		if existing.GoogleSubject != nil && *existing.GoogleSubject != subject {
			return domainuser.Users{}, false, domainuser.ErrGoogleTokenInvalid
		}
		extra := map[string]any{"google_subject": subject}
		// An account whose email was never verified may have been created by
		// someone who does not own the address. Linking takes it over, so
		// whatever credentials and sessions it had must stop working.
		if existing.EmailVerifiedAt == nil {
			randomHash, hashErr := s.randomPasswordHash()
			if hashErr != nil {
				return domainuser.Users{}, false, hashErr
			}
			extra["password"] = randomHash
			extra["password_changed_at"] = time.Now()
			extra["tokens_valid_after"] = time.Now()
		}
		user, created, err := s.finishGoogleLogin(ctx, existing, identity, metadata, extra)
		if err != nil {
			return domainuser.Users{}, false, err
		}
		if existing.EmailVerifiedAt == nil {
			s.invalidateUserPermissionCache(ctx, user.ID)
			if s.Sessions != nil {
				if err := s.Sessions.DestroyAllUserSessions(ctx, user.ID); err != nil {
					return domainuser.Users{}, false, fmt.Errorf("revoke sessions after google link: %w", err)
				}
			}
		}
		return user, created, nil
	}
	if !allowRegistration {
		return domainuser.Users{}, false, domainuser.ErrPublicRegistrationDisabled
	}

	roleName := s.defaultRole()
	roleID, ok := findRoleIDByName(ctx, s.RoleRepo, roleName)
	if !ok {
		return domainuser.Users{}, false, fmt.Errorf("role %s is not configured", roleName)
	}

	hashedPwd, err := s.randomPasswordHash()
	if err != nil {
		return domainuser.Users{}, false, err
	}

	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name = strings.Split(email, "@")[0]
	}

	user := domainuser.Users{
		ID:                 s.newID(),
		Name:               serviceshared.TitleCase(name),
		Email:              email,
		Phone:              "",
		Password:           hashedPwd,
		Role:               roleName,
		RoleID:             roleID,
		EmailVerifiedAt:    new(time.Now()),
		LastLoginAt:        new(time.Now()),
		LastLoginIP:        metadata.IP,
		LastLoginUserAgent: metadata.UserAgent,
		PasswordChangedAt:  new(time.Now()),
		GoogleSubject:      &subject,
		LoginProvider:      "google",
		AvatarURL:          strings.TrimSpace(identity.Picture),
		Metadata:           map[string]any{},
		CreatedAt:          time.Now(),
	}

	if err := s.UserRepo.Store(ctx, user); err != nil {
		return domainuser.Users{}, false, err
	}

	return user, true, nil
}

// finishGoogleLogin records the login with a column-scoped write; extra adds
// the linking columns.
func (s *Service) finishGoogleLogin(ctx context.Context, user domainuser.Users, identity googleTokenInfo, metadata dtouser.LoginMetadata, extra map[string]any) (domainuser.Users, bool, error) {
	now := time.Now()
	fields := map[string]any{
		"last_login_at":         now,
		"last_login_ip":         metadata.IP,
		"last_login_user_agent": metadata.UserAgent,
		"login_provider":        "google",
	}
	if user.EmailVerifiedAt == nil {
		fields["email_verified_at"] = now
		user.EmailVerifiedAt = &now
	}
	if picture := strings.TrimSpace(identity.Picture); picture != "" {
		fields["avatar_url"] = picture
		user.AvatarURL = picture
	}
	for k, v := range extra {
		fields[k] = v
	}
	if err := s.UserRepo.UpdateFields(ctx, user.ID, fields); err != nil {
		return domainuser.Users{}, false, err
	}
	user.LastLoginAt, user.LastLoginIP, user.LastLoginUserAgent, user.LoginProvider = &now, metadata.IP, metadata.UserAgent, "google"
	if subject, ok := fields["google_subject"].(string); ok {
		user.GoogleSubject = &subject
	}
	return user, false, nil
}

// randomPasswordHash is the hash of a random secret nobody knows, for accounts
// that sign in with Google.
func (s *Service) randomPasswordHash() (string, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	return hashPassword(hex.EncodeToString(seed))
}
