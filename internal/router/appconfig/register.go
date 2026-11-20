// Package appconfig mounts the app-config routes. Alias routerappconfig.
package appconfig

import (
	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Register mounts the app-config routes under r.
func Register(r gin.IRouter, d module.Deps) {
	h := d.AppConfig

	r.GET("/configs", d.Auth, d.Can("configs", "list"), h.GetAll)

	appConfig := r.Group("/config").Use(d.Auth)
	{
		appConfig.GET("/:id", d.Can("configs", "view"), h.GetByID)
		appConfig.PUT("/:id", d.Can("configs", "update"), h.Update)
	}
}
