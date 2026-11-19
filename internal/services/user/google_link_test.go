package user

import (
	"context"
	"errors"
	"testing"
	"time"

	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
)

type revokerDouble struct{ userIDs []string }

func (r *revokerDouble) DestroyAllUserSessions(_ context.Context, id string) error {
	r.userIDs = append(r.userIDs, id)
	return nil
}

func withGoogleIdentity(t *testing.T, id googleTokenInfo) {
	t.Helper()
	orig := googleIDTokenVerifier
	googleIDTokenVerifier = func(context.Context, string, []string) (googleTokenInfo, error) { return id, nil }
	t.Cleanup(func() { googleIDTokenVerifier = orig })
}

func googleService(t *testing.T, repo *userRepoMock) (*Service, *revokerDouble) {
	t.Helper()
	svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{roles: map[string]domainrole.Role{"viewer": {ID: "role-viewer", Name: "viewer"}}}, &permissionRepoUserMock{})
	rev := &revokerDouble{}
	svc.Sessions = rev
	return svc, rev
}

func sp(s string) *string { return &s }

func TestGoogleLoginMatchesBySubjectEvenWhenTheEmailChanged(t *testing.T) {
	withGoogleIdentity(t, googleTokenInfo{Email: "new-address@example.com", EmailVerified: "true", Subject: "sub-1"})
	repo := &userRepoMock{subjectUser: domainuser.Users{ID: "u1", Email: "old@example.com", GoogleSubject: sp("sub-1"), Role: "viewer"}}
	svc, _ := googleService(t, repo)
	user, created, err := svc.LoginWithGoogle(context.Background(), dtouser.GoogleLogin{IDToken: "t"}, dtouser.LoginMetadata{}, false)
	if err != nil || created || user.ID != "u1" {
		t.Fatalf("user=%+v created=%v err=%v", user, created, err)
	}
}

func TestGoogleLoginRejectsAnEmailLinkedToAnotherSubject(t *testing.T) {
	withGoogleIdentity(t, googleTokenInfo{Email: "jane@example.com", EmailVerified: "true", Subject: "attacker-sub"})
	repo := &userRepoMock{emailUser: domainuser.Users{ID: "u1", Email: "jane@example.com", GoogleSubject: sp("real-sub"), EmailVerifiedAt: new(time.Now())}}
	svc, _ := googleService(t, repo)
	if _, _, err := svc.LoginWithGoogle(context.Background(), dtouser.GoogleLogin{IDToken: "t"}, dtouser.LoginMetadata{}, true); !errors.Is(err, domainuser.ErrGoogleTokenInvalid) {
		t.Fatalf("err = %v, want ErrGoogleTokenInvalid", err)
	}
}

func TestGoogleLinkingAVerifiedLocalAccountKeepsThePassword(t *testing.T) {
	withGoogleIdentity(t, googleTokenInfo{Email: "jane@example.com", EmailVerified: "true", Subject: "sub-1"})
	repo := &userRepoMock{emailUser: domainuser.Users{ID: "u1", Email: "jane@example.com", Password: "keep", EmailVerifiedAt: new(time.Now())}}
	svc, rev := googleService(t, repo)
	if _, _, err := svc.LoginWithGoogle(context.Background(), dtouser.GoogleLogin{IDToken: "t"}, dtouser.LoginMetadata{}, true); err != nil {
		t.Fatal(err)
	}
	if repo.updated.ID != "" {
		t.Fatal("linking must not overwrite the whole user row")
	}
	if repo.fields["google_subject"] != "sub-1" {
		t.Errorf("google_subject = %v", repo.fields["google_subject"])
	}
	if _, ok := repo.fields["password"]; ok {
		t.Error("a verified account keeps its password")
	}
	if len(rev.userIDs) != 0 {
		t.Error("a verified account keeps its sessions")
	}
}

func TestGoogleLinkingAnUnverifiedLocalAccountResetsItsCredentials(t *testing.T) {
	withGoogleIdentity(t, googleTokenInfo{Email: "jane@example.com", EmailVerified: "true", Subject: "sub-1"})
	repo := &userRepoMock{emailUser: domainuser.Users{ID: "u1", Email: "jane@example.com", Password: "squatter-known-hash"}}
	svc, rev := googleService(t, repo)
	if _, _, err := svc.LoginWithGoogle(context.Background(), dtouser.GoogleLogin{IDToken: "t"}, dtouser.LoginMetadata{}, true); err != nil {
		t.Fatal(err)
	}
	pw, _ := repo.fields["password"].(string)
	if pw == "" || pw == "squatter-known-hash" {
		t.Errorf("password hash was not replaced: %q", pw)
	}
	if _, ok := repo.fields["tokens_valid_after"]; !ok {
		t.Error("tokens_valid_after was not bumped")
	}
	if repo.fields["email_verified_at"] == nil {
		t.Error("email_verified_at was not set")
	}
	if len(rev.userIDs) != 1 || rev.userIDs[0] != "u1" {
		t.Errorf("sessions revoked for %v, want u1", rev.userIDs)
	}
}

func TestGoogleRegistrationStoresTheSubject(t *testing.T) {
	withGoogleIdentity(t, googleTokenInfo{Email: "new@example.com", EmailVerified: "true", Subject: "sub-9", Name: "New"})
	repo := &userRepoMock{emailErr: domainuser.ErrNotFound}
	svc, _ := googleService(t, repo)
	user, created, err := svc.LoginWithGoogle(context.Background(), dtouser.GoogleLogin{IDToken: "t"}, dtouser.LoginMetadata{}, true)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if user.GoogleSubject == nil || *user.GoogleSubject != "sub-9" {
		t.Fatalf("GoogleSubject = %v", user.GoogleSubject)
	}
}
