package user

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	serviceshared "github.com/zazhedho/authkit/internal/services/shared"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type googleTokenInfo struct {
	Audience      string `json:"aud"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Subject       string `json:"sub"`
}

var googleIDTokenVerifier = verifyGoogleIDToken

func (s *Service) LoginWithGoogle(ctx context.Context, req dtouser.GoogleLogin, metadata dtouser.LoginMetadata, allowRegistration bool) (domainuser.Users, bool, error) {
	identity, err := googleIDTokenVerifier(ctx, req.IDToken, s.GoogleClientIDs)
	if err != nil {
		return domainuser.Users{}, false, err
	}

	email := domainuser.SanitizeEmail(identity.Email)
	if email == "" {
		return domainuser.Users{}, false, domainuser.ErrGoogleEmailMissing
	}

	existing, err := s.UserRepo.GetByEmail(ctx, email)
	if err == nil && existing.Id != "" {
		existing.EmailVerifiedAt = new(time.Now())
		existing.LastLoginAt = new(time.Now())
		existing.LastLoginIP = metadata.IP
		existing.LastLoginUserAgent = metadata.UserAgent
		existing.LoginProvider = "google"
		if strings.TrimSpace(identity.Picture) != "" {
			existing.AvatarURL = strings.TrimSpace(identity.Picture)
		}
		if updateErr := s.UserRepo.Update(ctx, existing); updateErr != nil {
			return domainuser.Users{}, false, updateErr
		}
		return existing, false, nil
	}
	if err != nil && !errors.Is(err, domainuser.ErrNotFound) {
		return domainuser.Users{}, false, err
	}
	if !allowRegistration {
		return domainuser.Users{}, false, domainuser.ErrPublicRegistrationDisabled
	}

	roleName := s.defaultRole()
	roleId, ok := findRoleIDByName(ctx, s.RoleRepo, roleName)
	if !ok {
		return domainuser.Users{}, false, fmt.Errorf("role %s is not configured", roleName)
	}

	passwordSeed := "Google-" + s.newID() + "-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "!"
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(passwordSeed), bcrypt.DefaultCost)
	if err != nil {
		return domainuser.Users{}, false, err
	}

	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name = strings.Split(email, "@")[0]
	}

	user := domainuser.Users{
		Id:                 s.newID(),
		Name:               serviceshared.TitleCase(name),
		Email:              email,
		Phone:              "",
		Password:           string(hashedPwd),
		Role:               roleName,
		RoleId:             roleId,
		EmailVerifiedAt:    new(time.Now()),
		LastLoginAt:        new(time.Now()),
		LastLoginIP:        metadata.IP,
		LastLoginUserAgent: metadata.UserAgent,
		PasswordChangedAt:  new(time.Now()),
		LoginProvider:      "google",
		AvatarURL:          strings.TrimSpace(identity.Picture),
		Metadata: map[string]any{
			"google_subject": identity.Subject,
		},
		CreatedAt: time.Now(),
	}

	if err := s.UserRepo.Store(ctx, user); err != nil {
		return domainuser.Users{}, false, err
	}

	return user, true, nil
}

func verifyGoogleIDToken(ctx context.Context, idToken string, clientIDs []string) (googleTokenInfo, error) {
	if strings.TrimSpace(idToken) == "" {
		return googleTokenInfo{}, domainuser.ErrGoogleTokenInvalid
	}

	allowedAudiences := googleAllowedAudiences(clientIDs)
	if len(allowedAudiences) == 0 {
		return googleTokenInfo{}, domainuser.ErrGoogleNotConfigured
	}

	endpoint := "https://oauth2.googleapis.com/tokeninfo?id_token=" + url.QueryEscape(idToken)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return googleTokenInfo{}, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return googleTokenInfo{}, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return googleTokenInfo{}, domainuser.ErrGoogleTokenInvalid
	}

	var tokenInfo googleTokenInfo
	if err := json.NewDecoder(response.Body).Decode(&tokenInfo); err != nil {
		return googleTokenInfo{}, err
	}

	if _, ok := allowedAudiences[strings.TrimSpace(tokenInfo.Audience)]; !ok {
		return googleTokenInfo{}, domainuser.ErrGoogleTokenInvalid
	}
	if !strings.EqualFold(strings.TrimSpace(tokenInfo.EmailVerified), "true") {
		return googleTokenInfo{}, domainuser.ErrGoogleTokenInvalid
	}
	if domainuser.SanitizeEmail(tokenInfo.Email) == "" {
		return googleTokenInfo{}, domainuser.ErrGoogleEmailMissing
	}
	if strings.TrimSpace(tokenInfo.Subject) == "" {
		return googleTokenInfo{}, domainuser.ErrGoogleTokenInvalid
	}

	return tokenInfo, nil
}

func googleAllowedAudiences(clientIDs []string) map[string]struct{} {
	values := make(map[string]struct{}, len(clientIDs))
	for _, item := range clientIDs {
		if normalized := strings.TrimSpace(item); normalized != "" {
			values[normalized] = struct{}{}
		}
	}
	return values
}
