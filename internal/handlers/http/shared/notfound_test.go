package shared

import (
	"errors"
	"fmt"
	"testing"

	domainappconfig "github.com/zazhedho/authkit/internal/domain/appconfig"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainotp "github.com/zazhedho/authkit/internal/domain/otp"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
	domainreset "github.com/zazhedho/authkit/internal/domain/reset"
	domainrole "github.com/zazhedho/authkit/internal/domain/role"
	domainsession "github.com/zazhedho/authkit/internal/domain/session"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

func TestIsNotFoundMatchesEveryDomainSentinel(t *testing.T) {
	sentinels := map[string]error{
		"appconfig":  domainappconfig.ErrNotFound,
		"audit":      domainaudit.ErrNotFound,
		"auth":       domainauth.ErrNotFound,
		"menu":       domainmenu.ErrNotFound,
		"otp":        domainotp.ErrNotFound,
		"permission": domainpermission.ErrNotFound,
		"reset":      domainreset.ErrNotFound,
		"role":       domainrole.ErrNotFound,
		"session":    domainsession.ErrNotFound,
		"user":       domainuser.ErrNotFound,
	}
	for name, err := range sentinels {
		if !IsNotFound(err) {
			t.Errorf("%s: IsNotFound(%v) = false", name, err)
		}
		if !IsNotFound(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("%s: IsNotFound(wrapped) = false", name)
		}
	}
}

func TestIsNotFoundRejectsOtherErrors(t *testing.T) {
	for _, err := range []error{nil, errors.New("boom"), domainrole.ErrDuplicate, domainuser.ErrDuplicate} {
		if IsNotFound(err) {
			t.Errorf("IsNotFound(%v) = true", err)
		}
	}
}
