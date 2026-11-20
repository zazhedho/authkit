package user

import (
	"context"
	"errors"
	"testing"
	"time"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"

	"golang.org/x/crypto/bcrypt"
)

func perm(resource, action string) domainpermission.Permission {
	return domainpermission.Permission{ID: resource + action, Name: resource + "_" + action, Resource: resource, Action: action}
}

type ruleEnv struct {
	svc   *Service
	users *userRepoMock
	perms *permissionRepoUserMock
}

// newRuleEnv builds a service where "admin" holds users:update and
// users:delete, "staff" holds users:update only, "viewer" holds nothing.
func newRuleEnv(t *testing.T, target domainuser.Users) ruleEnv {
	t.Helper()
	users := &userRepoMock{usersByID: map[string]domainuser.Users{target.ID: target, "staff-1": {ID: "staff-1", Role: "staff"}}, superAdmins: 2}
	perms := &permissionRepoUserMock{rolePermissions: map[string][]domainpermission.Permission{
		"admin":  {perm("users", "update"), perm("users", "delete"), perm("roles", "update")},
		"staff":  {perm("users", "update")},
		"viewer": {},
	}}
	roles := &roleRepoUserMock{roles: map[string]domainrole.Role{
		"admin":      {ID: "r-admin", Name: "admin"},
		"staff":      {ID: "r-staff", Name: "staff"},
		"viewer":     {ID: "r-viewer", Name: "viewer"},
		"superadmin": {ID: "r-super", Name: "superadmin"},
	}}
	return ruleEnv{svc: newTestUserService(t, users, &authRepoMock{}, roles, perms), users: users, perms: perms}
}

func staffActor() domainauth.Actor {
	return authActor("staff-1", "Staff", "staff", "users:update", "users:assign_role", "users:delete")
}

func TestUpdateRefusesATargetWhoseRoleOutranksTheActor(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "adm", Role: "admin", Email: "a@x.io"})
	_, err := env.svc.Update(context.Background(), staffActor(), "adm", dtouser.Update{Email: "evil@x.io"})
	if !errors.Is(err, domainuser.ErrRoleAboveActor) {
		t.Fatalf("got %v, want ErrRoleAboveActor", err)
	}
	if env.users.updated.ID != "" || len(env.users.fields) != 0 {
		t.Fatal("target must not be written")
	}
}

func TestDeleteRefusesATargetWhoseRoleOutranksTheActor(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "adm", Role: "admin"})
	err := env.svc.Delete(context.Background(), staffActor(), "adm")
	if !errors.Is(err, domainuser.ErrRoleAboveActor) {
		t.Fatalf("got %v, want ErrRoleAboveActor", err)
	}
	if env.users.deletedID != "" {
		t.Fatal("target must not be deleted")
	}
}

func TestDeleteRefusesSuperadminForNonSuperadmin(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "su", Role: "superadmin"})
	if err := env.svc.Delete(context.Background(), staffActor(), "su"); !errors.Is(err, domainuser.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestDeleteRefusesTheLastSuperadmin(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "su", Role: "superadmin"})
	env.users.superAdmins = 1
	actor := authActor("su-2", "Other", "superadmin")
	if err := env.svc.Delete(context.Background(), actor, "su"); !errors.Is(err, domainuser.ErrLastSuperAdmin) {
		t.Fatalf("got %v", err)
	}
	if err := env.svc.Delete(context.Background(), authActor("su", "Me", "superadmin"), "su"); !errors.Is(err, domainuser.ErrLastSuperAdmin) {
		t.Fatalf("self delete of the last superadmin: got %v", err)
	}
}

func TestDeleteAllowsACoveredTargetAndRevokesTokens(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "stf", Role: "staff"})
	if err := env.svc.Delete(context.Background(), staffActor(), "stf"); err != nil {
		t.Fatal(err)
	}
	if env.users.deletedID != "stf" {
		t.Fatal("expected delete")
	}
}

func TestDeleteSelfIsAllowedForOrdinaryUsers(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "staff-1", Role: "staff"})
	if err := env.svc.Delete(context.Background(), staffActor(), "staff-1"); err != nil {
		t.Fatal(err)
	}
}

func TestNobodyMayChangeTheirOwnRole(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "staff-1", Role: "staff"})
	_, err := env.svc.Update(context.Background(), authActor("staff-1", "S", "staff", "users:assign_role"), "staff-1", dtouser.Update{Role: "admin"})
	if !errors.Is(err, domainuser.ErrSelfRoleChange) {
		t.Fatalf("got %v", err)
	}
	su := newRuleEnv(t, domainuser.Users{ID: "su", Role: "superadmin"})
	_, err = su.svc.Update(context.Background(), authActor("su", "S", "superadmin"), "su", dtouser.Update{Role: "viewer"})
	if !errors.Is(err, domainuser.ErrSelfRoleChange) {
		t.Fatalf("superadmin self demotion: got %v", err)
	}
}

func TestAssignRoleRequiresTheActorToHoldEveryPermissionOfTheRole(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "v", Role: "viewer"})
	_, err := env.svc.Update(context.Background(), staffActor(), "v", dtouser.Update{Role: "admin"})
	if !errors.Is(err, domainuser.ErrRoleAboveActor) {
		t.Fatalf("got %v", err)
	}
	if _, err := env.svc.Update(context.Background(), staffActor(), "v", dtouser.Update{Role: "staff"}); err != nil {
		t.Fatalf("covered role must be assignable: %v", err)
	}
}

func TestDemotingTheLastSuperadminIsRefused(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "su", Role: "superadmin"})
	env.users.superAdmins = 1
	_, err := env.svc.Update(context.Background(), authActor("other", "O", "superadmin"), "su", dtouser.Update{Role: "viewer"})
	if !errors.Is(err, domainuser.ErrLastSuperAdmin) {
		t.Fatalf("got %v", err)
	}
}

func TestRoleChangeBumpsTokensValidAfter(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "v", Role: "viewer"})
	if _, err := env.svc.Update(context.Background(), staffActor(), "v", dtouser.Update{Role: "staff"}); err != nil {
		t.Fatal(err)
	}
	if !env.users.revoked || env.users.fields["role"] != "staff" {
		t.Fatalf("the role must change together with the cut-off: revoked=%v fields=%v", env.users.revoked, env.users.fields)
	}
}

func hash(t *testing.T, pw string) string {
	t.Helper()
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSelfServiceEmailChangeNeedsTheCurrentPassword(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "staff-1", Role: "staff", Email: "me@x.io", Password: hash(t, "Passw0rd!x")})
	self := authActor("staff-1", "S", "staff")
	_, err := env.svc.Update(context.Background(), self, "staff-1", dtouser.Update{Email: "new@x.io"})
	if !errors.Is(err, domainuser.ErrPasswordRequired) {
		t.Fatalf("got %v", err)
	}
	_, err = env.svc.Update(context.Background(), self, "staff-1", dtouser.Update{Email: "new@x.io", CurrentPassword: "wrong"})
	if !errors.Is(err, domainuser.ErrPasswordIncorrect) {
		t.Fatalf("got %v", err)
	}
	got, err := env.svc.Update(context.Background(), self, "staff-1", dtouser.Update{Email: "new@x.io", CurrentPassword: "Passw0rd!x"})
	if err != nil || got.Email != "new@x.io" {
		t.Fatalf("got %v %v", got.Email, err)
	}
	if got.EmailVerifiedAt != nil {
		t.Fatal("email change must reset verification")
	}
	if !env.users.revoked {
		t.Fatal("email change must revoke tokens in the same write")
	}
}

func TestAdminEmailChangeResetsVerification(t *testing.T) {
	verified := time.Now()
	env := newRuleEnv(t, domainuser.Users{ID: "v", Role: "viewer", Email: "v@x.io", EmailVerifiedAt: &verified})
	got, err := env.svc.Update(context.Background(), staffActor(), "v", dtouser.Update{Email: "other@x.io"})
	if err != nil || got.EmailVerifiedAt != nil {
		t.Fatalf("verified=%v err=%v", got.EmailVerifiedAt, err)
	}
}

func TestUpdateRejectsAnEmailThatSanitizesToEmpty(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "v", Role: "viewer", Email: "v@x.io"})
	_, err := env.svc.Update(context.Background(), staffActor(), "v", dtouser.Update{Email: "Jane <j@x.io>"})
	if !errors.Is(err, domainuser.ErrEmailRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestAdminCreateUserRefusesARoleTheActorDoesNotCover(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{})
	env.users.emailErr = domainuser.ErrNotFound
	_, err := env.svc.AdminCreateUser(context.Background(), staffActor(), dtouser.AdminCreateUser{
		Name: "Jane Roe", Email: "j@x.io", Password: "Passw0rd!x", Role: "admin"})
	if !errors.Is(err, domainuser.ErrRoleAboveActor) {
		t.Fatalf("got %v", err)
	}
}

func TestImpersonationFollowsTheRoleRule(t *testing.T) {
	env := newRuleEnv(t, domainuser.Users{ID: "adm", Role: "admin", Name: "Adm"})
	_, err := env.svc.ImpersonateUser(context.Background(), staffActor(), "adm", "ticket 42")
	if !errors.Is(err, domainuser.ErrRoleAboveActor) {
		t.Fatalf("got %v", err)
	}
}
