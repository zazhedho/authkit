package shared

import (
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

// HideSuperAdmin finishes a list query for a caller. Anyone but a superadmin
// does not see the rows isSuperAdmin reports, and total drops by the number
// hidden so the page count stays consistent. A failed query passes through.
func HideSuperAdmin[T any](actor domainauth.Actor, items []T, total int64, err error, isSuperAdmin func(T) bool) ([]T, int64, error) {
	if err != nil {
		return nil, 0, err
	}
	if actor.Role == domainuser.RoleSuperAdmin {
		return items, total, nil
	}

	visible := make([]T, 0, len(items))
	for _, item := range items {
		if !isSuperAdmin(item) {
			visible = append(visible, item)
		}
	}
	return visible, total - int64(len(items)-len(visible)), nil
}
