// Package menu mounts the menu routes. Alias routermenu.
package menu

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Register mounts the menu routes under r.
func Register(r gin.IRouter, d module.Deps) error {
	if d.Menu == nil {
		return errors.New("router: the menu handler is missing")
	}
	h := d.Menu

	// Available to any authenticated user.
	r.GET("/menus/active", d.Auth, h.GetActiveMenus)
	r.GET("/menus/me", d.Auth, h.GetUserMenus)

	r.GET("/menus", d.Auth, d.Can("menus", "list"), h.GetAll)

	menu := r.Group("/menu").Use(d.Auth)
	{
		menu.GET("/:id", d.Can("menus", "view"), h.GetByID)
		menu.PUT("/:id", d.Can("menus", "update"), h.Update)
	}
	return nil
}
