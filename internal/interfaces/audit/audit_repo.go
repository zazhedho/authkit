package interfaceaudit

import (
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	"github.com/zazhedho/gokit"
)

type RepoAuditInterface interface {
	gokit.CRUDRepository[domainaudit.AuditTrail]
}
