package user

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	domainuser "github.com/zazhedho/authkit/internal/domain/user"
	dtouser "github.com/zazhedho/authkit/internal/dto/user"
)

// weakCost is below the test passwordCost, so a login rehashes it.
const weakCost = bcrypt.MinCost

func TestMain(m *testing.M) {
	passwordCost = 6
	os.Exit(m.Run())
}

func hashAt(t *testing.T, password string, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func loginService(t *testing.T, repo *userRepoMock, phoneLogin bool) *Service {
	svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	svc.PhoneLogin = phoneLogin
	return svc
}

func TestLoginMissingUserIsInvalidCredentialsAfterAHashComparison(t *testing.T) {
	svc := loginService(t, &userRepoMock{emailErr: domainuser.ErrNotFound}, false)
	_, err := svc.LoginUser(context.Background(), dtouser.Login{Identifier: "nobody@example.com", Password: "Passw0rd!x"}, "log", dtouser.LoginMetadata{})
	if !errors.Is(err, domainuser.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWrongPasswordIsInvalidCredentials(t *testing.T) {
	svc := loginService(t, &userRepoMock{emailUser: domainuser.Users{ID: "u", Password: hashAt(t, "Passw0rd!x", weakCost)}}, false)
	_, err := svc.LoginUser(context.Background(), dtouser.Login{Identifier: "a@example.com", Password: "wrong"}, "log", dtouser.LoginMetadata{})
	if !errors.Is(err, domainuser.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginMalformedHashCountsAsInvalidCredentials(t *testing.T) {
	svc := loginService(t, &userRepoMock{emailUser: domainuser.Users{ID: "u", Password: strings.Repeat("x", 12)}}, false) //nolint:gosec // a malformed hash, not a credential
	_, err := svc.LoginUser(context.Background(), dtouser.Login{Identifier: "a@example.com", Password: "Passw0rd!x"}, "log", dtouser.LoginMetadata{})
	if !errors.Is(err, domainuser.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginByPhoneIsOffByDefault(t *testing.T) {
	repo := &userRepoMock{phoneUser: domainuser.Users{ID: "u", Password: hashAt(t, "Passw0rd!x", weakCost)}}
	_, err := loginService(t, repo, false).LoginUser(context.Background(), dtouser.Login{Identifier: "081234567890", Password: "Passw0rd!x"}, "log", dtouser.LoginMetadata{})
	if !errors.Is(err, domainuser.ErrInvalidCredentials) {
		t.Fatalf("phone login while off: err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := loginService(t, repo, true).LoginUser(context.Background(), dtouser.Login{Identifier: "081234567890", Password: "Passw0rd!x"}, "log", dtouser.LoginMetadata{}); err != nil {
		t.Fatalf("phone login while on: %v", err)
	}
}

func TestLoginWritesOnlyTheLoginColumnsAndRehashesALowCostHash(t *testing.T) {
	repo := &userRepoMock{emailUser: domainuser.Users{ID: "u", Name: "N", Role: "viewer", Password: hashAt(t, "Passw0rd!x", weakCost)}}
	svc := loginService(t, repo, false)
	if _, err := svc.LoginUser(context.Background(), dtouser.Login{Identifier: "a@example.com", Password: "Passw0rd!x"}, "log", dtouser.LoginMetadata{IP: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if repo.updated.ID != "" {
		t.Fatal("login must not overwrite the whole user row")
	}
	for _, col := range []string{"last_login_at", "last_login_ip", "last_login_user_agent", "login_provider", "password"} {
		if _, ok := repo.fields[col]; !ok {
			t.Errorf("column %s was not written", col)
		}
	}
	cost, err := bcrypt.Cost([]byte(repo.fields["password"].(string)))
	if err != nil || cost != passwordCost {
		t.Errorf("rehash cost = %d err=%v, want %d", cost, err, passwordCost)
	}

	// A hash already at the current cost is left alone.
	repo = &userRepoMock{emailUser: domainuser.Users{ID: "u", Password: hashAt(t, "Passw0rd!x", passwordCost)}}
	if _, err := loginService(t, repo, false).LoginUser(context.Background(), dtouser.Login{Identifier: "a@example.com", Password: "Passw0rd!x"}, "log", dtouser.LoginMetadata{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := repo.fields["password"]; ok {
		t.Error("a hash at the current cost must not be rewritten")
	}
}

func TestPasswordsOver72BytesAreRejected(t *testing.T) {
	long := "Aa1!" + strings.Repeat("x", 70)
	if err := ValidatePasswordStrength(long); !errors.Is(err, domainuser.ErrPasswordTooLong) {
		t.Fatalf("err = %v, want ErrPasswordTooLong", err)
	}
	if err := ValidatePasswordStrength("Aa1!" + strings.Repeat("x", 68)); err != nil {
		t.Fatalf("72 bytes must pass: %v", err)
	}
	if err := ValidatePasswordStrength("short"); !errors.Is(err, domainuser.ErrWeakPassword) {
		t.Fatalf("err = %v, want ErrWeakPassword", err)
	}
}

func TestRegisterConflictDoesNotRevealWhichFieldExists(t *testing.T) {
	for name, repo := range map[string]*userRepoMock{
		"email": {emailUser: domainuser.Users{ID: "x"}},
		"phone": {phoneUser: domainuser.Users{ID: "x"}},
	} {
		svc := newTestUserService(t, repo, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
		_, err := svc.RegisterUser(context.Background(), dtouser.Register{Name: "Jane", Email: "j@example.com", Phone: "081234567890", Password: "Passw0rd!x"})
		if !errors.Is(err, domainuser.ErrDuplicate) {
			t.Fatalf("%s: err = %v, want ErrDuplicate", name, err)
		}
		if strings.Contains(err.Error(), "email already") || strings.Contains(err.Error(), "phone number already") {
			t.Errorf("%s: message reveals the field: %v", name, err)
		}
	}
}

func TestRegisterSurfacesDuplicateCheckFailures(t *testing.T) {
	boom := errors.New("db down")
	svc := newTestUserService(t, &userRepoMock{emailErr: boom}, &authRepoMock{}, &roleRepoUserMock{}, &permissionRepoUserMock{})
	if _, err := svc.RegisterUser(context.Background(), dtouser.Register{Name: "Jane", Email: "j@example.com", Phone: "081234567890", Password: "Passw0rd!x"}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the lookup error", err)
	}
}
