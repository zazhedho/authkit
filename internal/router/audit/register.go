// Package audit mounts the audit routes. Alias routeraudit.
package audit

import (
	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Register mounts the audit routes under r.
func Register(r gin.IRouter, d module.Deps) {
	h := d.Audit

	r.GET("/audits", d.Auth, d.Can("audits", "list"), h.GetAll)

	audit := r.Group("/audit").Use(d.Auth)
	{
		audit.GET("/:id", d.Can("audits", "view"), h.GetByID)
	}
}
