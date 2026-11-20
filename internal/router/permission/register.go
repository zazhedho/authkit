// Package permission mounts the permission routes. Alias routerpermission.
package permission

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Register mounts the permission routes under r.
func Register(r gin.IRouter, d module.Deps) error {
	if d.Permission == nil {
		return errors.New("router: the permission handler is missing")
	}
	h := d.Permission

	r.GET("/permissions", d.Auth, d.Can("permissions", "list"), h.GetAll)

	// Current user's permissions: authentication only.
	r.GET("/permissions/me", d.Auth, h.GetUserPermissions)

	permission := r.Group("/permission").Use(d.Auth)
	{
		permission.POST("", d.Can("permissions", "create"), h.Create)
		permission.GET("/:id", d.Can("permissions", "view"), h.GetByID)
		permission.PUT("/:id", d.Can("permissions", "update"), h.Update)
		permission.DELETE("/:id", d.Can("permissions", "delete"), h.Delete)
	}
	return nil
}
