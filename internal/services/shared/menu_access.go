package shared

import (
	"context"
	"strings"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainmenu "github.com/zazhedho/authkit/internal/domain/menu"
	domainpermission "github.com/zazhedho/authkit/internal/domain/permission"
)

// ResolveAccessibleMenus resolves the accessible menus.
func ResolveAccessibleMenus(activeMenus []domainmenu.Item, resources []string) []domainmenu.Item {
	if len(activeMenus) == 0 || len(resources) == 0 {
		return []domainmenu.Item{}
	}

	menuByID := make(map[string]domainmenu.Item, len(activeMenus))
	menuByName := make(map[string]domainmenu.Item, len(activeMenus))
	for _, menu := range activeMenus {
		menuByID[menu.ID] = menu
		menuByName[menu.Name] = menu
	}

	allowedIDs := make(map[string]struct{})
	for _, resource := range resources {
		menu, exists := menuByName[resource]
		if !exists {
			continue
		}
		addMenuAncestors(menu, menuByID, allowedIDs)
	}

	ret := make([]domainmenu.Item, 0, len(allowedIDs))
	for _, menu := range activeMenus {
		if _, exists := allowedIDs[menu.ID]; exists {
			ret = append(ret, menu)
		}
	}

	return ret
}

func addMenuAncestors(menu domainmenu.Item, menuByID map[string]domainmenu.Item, allowedIDs map[string]struct{}) {
	allowedIDs[menu.ID] = struct{}{}
	parentID := menu.ParentID
	for parentID != nil && *parentID != "" {
		parentMenu, exists := menuByID[*parentID]
		if !exists || !parentMenu.IsActive || parentMenu.DeletedAt.Valid {
			return
		}
		allowedIDs[parentMenu.ID] = struct{}{}
		parentID = parentMenu.ParentID
	}
}

// ResolveAccessibleMenuIDs resolves the accessible menu i ds.
func ResolveAccessibleMenuIDs(activeMenus []domainmenu.Item, resources []string) []string {
	menus := ResolveAccessibleMenus(activeMenus, resources)
	ids := make([]string, 0, len(menus))
	for _, menu := range menus {
		ids = append(ids, menu.ID)
	}

	return ids
}

// HasPermission reports whether actor holds (resource, action). An actor
// whose permissions were not loaded is checked against the repository.
func HasPermission(ctx context.Context, permissionRepo PermissionRepository, actor domainauth.Actor, resource, action string) (bool, error) {
	if actor.Has(resource, action) {
		return true, nil
	}

	if len(actor.Permissions) > 0 || strings.TrimSpace(actor.UserID) == "" {
		return false, nil
	}

	permissions, err := permissionRepo.GetUserPermissions(ctx, actor.UserID)
	if err != nil {
		return false, err
	}

	return permissionListHasAccess(permissions, resource, action), nil
}

func permissionListHasAccess(permissions []domainpermission.Permission, resource, action string) bool {
	targetKey := domainauth.PermissionKey(resource, action)
	if targetKey == "" {
		return false
	}

	for _, permission := range permissions {
		if domainauth.PermissionKey(permission.Resource, permission.Action) == targetKey {
			return true
		}
	}

	return false
}
