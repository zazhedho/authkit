package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
)

func hashedUser(t *testing.T, id, password string) domainuser.Users {
	t.Helper()
	return domainuser.Users{ID: id, Name: "N", Email: id + "@x.io", Role: "viewer", Password: hashAt(t, password, passwordCost)}
}

func withSessions(svc *Service) *revokerDouble {
	rev := &revokerDouble{}
	svc.sessions = rev
	return rev
}

func TestStopImpersonationChecksTheOriginalUser(t *testing.T) {
	admin := domainuser.Users{ID: "admin-1", Name: "Admin", Role: "admin"}
	actor := impersonatedActor("target-1", "T", "viewer", "admin-1", "Admin", "admin")
	issuedMS := time.Now().UnixMilli()

	t.Run("original deleted", func(t *testing.T) {
		svc := newTestUserService(t, &userRepoMock{usersByID: map[string]domainuser.Users{}}, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
		_, err := svc.StopImpersonation(context.Background(), actor, issuedMS)
		if !errors.Is(err, domainuser.ErrImpersonatorRevoked) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("original revoked since the impersonation token was issued", func(t *testing.T) {
		cutoff := time.UnixMilli(issuedMS + 5)
		admin := admin
		admin.TokensValidAfter = &cutoff
		svc := newTestUserService(t, &userRepoMock{usersByID: map[string]domainuser.Users{"admin-1": admin}}, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
		if _, err := svc.StopImpersonation(context.Background(), actor, issuedMS); !errors.Is(err, domainuser.ErrImpersonatorRevoked) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("restored token has no session and is issued after the cut-off", func(t *testing.T) {
		cutoff := time.UnixMilli(issuedMS - 10)
		admin := admin
		admin.TokensValidAfter = &cutoff
		svc := newTestUserService(t, &userRepoMock{usersByID: map[string]domainuser.Users{"admin-1": admin}}, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
		raw, err := svc.StopImpersonation(context.Background(), actor, issuedMS)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := testUserTokens(t).Claims(raw)
		if err != nil {
			t.Fatal(err)
		}
		if claims["no_session"] != true {
			t.Fatalf("the restored token must be marked no_session: %v", claims)
		}
		if ms, _ := claims["iat_ms"].(float64); int64(ms) <= cutoff.UnixMilli() {
			t.Fatalf("iat_ms %v is not after the cut-off", ms)
		}
	})
}

func TestImpersonationNeedsALiveActor(t *testing.T) {
	svc := newTestUserService(t, &userRepoMock{usersByID: map[string]domainuser.Users{"target-1": {ID: "target-1", Role: "viewer"}}}, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	_, err := svc.ImpersonateUser(context.Background(), authActor("admin-1", "A", "admin"), "target-1", "case", domainuser.ActorBinding{})
	if !errors.Is(err, domainuser.ErrImpersonatorRevoked) {
		t.Fatalf("err = %v", err)
	}
}

func TestRegisterHashesBeforeTheDuplicateCheck(t *testing.T) {
	// A 73-byte password fails at hashing; reaching that error for a taken
	// address proves the duplicate check runs after the hash.
	svc := newTestUserService(t, &userRepoMock{emailUser: domainuser.Users{ID: "x"}}, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	_, err := svc.RegisterUser(context.Background(), dtouser.Register{Name: "Jane", Email: "j@x.io", Password: "Aa1!" + strings.Repeat("x", 70)})
	if !errors.Is(err, domainuser.ErrPasswordTooLong) {
		t.Fatalf("err = %v", err)
	}
}

func TestChangePasswordWritesHashAndCutoffTogether(t *testing.T) {
	repo := &userRepoMock{user: hashedUser(t, "u1", "OldPassw0rd!")}
	svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	cutoff, err := svc.ChangePassword(context.Background(), "u1", dtouser.ChangePassword{CurrentPassword: "OldPassw0rd!", NewPassword: "NewPassw0rd!"})
	if err != nil || !repo.revoked || !cutoff.Equal(repo.cutoff) {
		t.Fatalf("cutoff=%v revoked=%v err=%v", cutoff, repo.revoked, err)
	}
	for _, col := range []string{"password", "password_changed_at"} {
		if _, ok := repo.fields[col]; !ok {
			t.Errorf("%s not written", col)
		}
	}

	repo = &userRepoMock{user: hashedUser(t, "u1", "OldPassw0rd!")}
	svc = newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	_, err = svc.ChangePassword(context.Background(), "u1", dtouser.ChangePassword{CurrentPassword: "Wrong1234!x", NewPassword: "NewPassw0rd!"})
	if !errors.Is(err, domainuser.ErrPasswordIncorrect) || repo.revoked {
		t.Fatalf("a wrong current password must change nothing: err=%v revoked=%v", err, repo.revoked)
	}
}

func TestResetPasswordDoesNotTurnADatabaseErrorIntoNotFound(t *testing.T) {
	boom := errors.New("db down")
	svc := newTestUserService(t, &userRepoMock{emailErr: boom}, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	err := svc.ResetPasswordByEmail(context.Background(), "a@x.io", "NewPassw0rd!")
	if !errors.Is(err, boom) || errors.Is(err, domainuser.ErrNotFound) {
		t.Fatalf("err = %v, want the database error", err)
	}
}

func TestResetPasswordRevokesInOneWriteAndEndsSessions(t *testing.T) {
	repo := &userRepoMock{emailUser: hashedUser(t, "u1", "OldPassw0rd!")}
	svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	rev := withSessions(svc)
	if err := svc.ResetPasswordByEmail(context.Background(), "u1@x.io", "NewPassw0rd!"); err != nil {
		t.Fatal(err)
	}
	if !repo.revoked || len(rev.userIDs) != 1 {
		t.Fatalf("revoked=%v sessions ended=%v", repo.revoked, rev.userIDs)
	}
}

func TestUpdateRevokesOnlyForCredentialChanges(t *testing.T) {
	cases := []struct {
		name       string
		phoneLogin bool
		req        dtouser.Update
		wantRevoke bool
		wantField  string
	}{
		{"name only", false, dtouser.Update{Name: "New Name"}, false, "name"},
		{"phone while phone login is off", false, dtouser.Update{Phone: "081299990000"}, false, "phone"},
		{"phone while phone login is on", true, dtouser.Update{Phone: "081299990000"}, true, "phone"},
		{"email", false, dtouser.Update{Email: "new@x.io"}, true, "email"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := hashedUser(t, "u1", "Passw0rd!x")
			u.Phone = "6281200000000"
			repo := &userRepoMock{user: u, emailErr: domainuser.ErrNotFound, phoneErr: domainuser.ErrNotFound}
			svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
			svc.PhoneLogin = tc.phoneLogin
			rev := withSessions(svc)
			tc.req.CurrentPassword = "Passw0rd!x"
			if _, err := svc.Update(context.Background(), authActor("u1", "N", "viewer"), "u1", tc.req); err != nil {
				t.Fatal(err)
			}
			if repo.revoked != tc.wantRevoke {
				t.Fatalf("revoked = %v, want %v", repo.revoked, tc.wantRevoke)
			}
			if _, ok := repo.fields[tc.wantField]; !ok {
				t.Fatalf("%s not written: %v", tc.wantField, repo.fields)
			}
			if got := len(rev.userIDs) == 1; got != tc.wantRevoke {
				t.Fatalf("sessions ended = %v, want %v", rev.userIDs, tc.wantRevoke)
			}
		})
	}
}

func TestEmailChangeClearsVerificationInTheSameWrite(t *testing.T) {
	repo := &userRepoMock{user: hashedUser(t, "u1", "Passw0rd!x"), emailErr: domainuser.ErrNotFound}
	svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	if _, err := svc.Update(context.Background(), authActor("u1", "N", "viewer"), "u1", dtouser.Update{Email: "new@x.io", CurrentPassword: "Passw0rd!x"}); err != nil {
		t.Fatal(err)
	}
	if v, ok := repo.fields["email_verified_at"]; !ok || v != nil {
		t.Fatalf("email_verified_at must be written as NULL with the email: %v", repo.fields)
	}
}

func TestDeleteEndsTheUsersSessions(t *testing.T) {
	repo := &userRepoMock{user: hashedUser(t, "u1", "Passw0rd!x"), superAdmins: 2}
	svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	rev := withSessions(svc)
	if err := svc.Delete(context.Background(), authActor("u1", "N", "viewer"), "u1"); err != nil {
		t.Fatal(err)
	}
	if len(rev.userIDs) != 1 || rev.userIDs[0] != "u1" {
		t.Fatalf("sessions ended = %v", rev.userIDs)
	}
}

func TestLastSuperAdminRulesLiveInTheRepositoryCall(t *testing.T) {
	root := domainuser.Users{ID: "root", Role: domainuser.RoleSuperAdmin}
	repo := &userRepoMock{user: root, superAdmins: 1}
	svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	if err := svc.Delete(context.Background(), authActor("root", "R", domainuser.RoleSuperAdmin), "root"); !errors.Is(err, domainuser.ErrLastSuperAdmin) {
		t.Fatalf("err = %v", err)
	}
}

func TestBlacklistExpiryOutlivesTheTokenSoAPurgedRowCannotMatterAgain(t *testing.T) {
	blacklist := &authRepoMock{}
	svc := newTestUserService(t, &userRepoMock{}, blacklist, &roleRepoUserMock{}, &permissionRepoUserMock{})
	raw, err := testUserTokens(t).Generate("u1", "N", "viewer", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	exp, _ := testUserTokens(t).ExpiresAt(raw)
	if err := svc.LogoutUser(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if got := blacklist.stored.ExpiresAt; got.Before(exp.Add(blacklistGrace)) {
		t.Fatalf("blacklist expiry %v is not at least exp+grace (%v)", got, exp.Add(blacklistGrace))
	}
}
