package shared

import (
	"errors"

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

var notFoundErrors = []error{
	domainappconfig.ErrNotFound,
	domainaudit.ErrNotFound,
	domainauth.ErrNotFound,
	domainmenu.ErrNotFound,
	domainotp.ErrNotFound,
	domainpermission.ErrNotFound,
	domainreset.ErrNotFound,
	domainrole.ErrNotFound,
	domainsession.ErrNotFound,
	domainuser.ErrNotFound,
}

// IsNotFound reports whether err wraps any module's ErrNotFound. A mutation can
// surface a missing row of another module, such as a deleted acting user.
func IsNotFound(err error) bool {
	for _, target := range notFoundErrors {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
