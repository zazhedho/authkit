package interfaceaudit

import (
	domainaudit "github.com/zazhedho/authkit/domain/audit"
	interfacegeneric "github.com/zazhedho/gokit/repository"
)

type RepoAuditInterface interface {
	interfacegeneric.GenericRepository[domainaudit.AuditTrail]
}
