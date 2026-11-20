// Package role mounts the role routes. Alias routerrole.
package role

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Register mounts the role routes under r.
func Register(r gin.IRouter, d module.Deps) error {
	if d.Role == nil {
		return errors.New("router: the role handler is missing")
	}
	h := d.Role

	r.GET("/roles", d.Auth, d.Can("roles", "list"), h.GetAll)

	role := r.Group("/role").Use(d.Auth)
	{
		role.POST("", d.Can("roles", "create"), h.Create)
		role.GET("/:id", d.Can("roles", "view"), h.GetByID)
		role.PUT("/:id", d.Can("roles", "update"), h.Update)
		role.DELETE("/:id", d.Can("roles", "delete"), h.Delete)

		role.POST("/:id/permissions", d.Can("roles", "assign_permissions"), h.AssignPermissions)
	}
	return nil
}
