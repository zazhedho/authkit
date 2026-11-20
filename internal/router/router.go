// Package router wires the users, auth and RBAC modules and mounts their
// routes. It opens nothing; the caller passes in every connection.
package router

import (
	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Mount registers every module's routes on r. Call it once per group: gin
// panics on duplicate routes.
func Mount(r gin.IRouter, d module.Deps) {
	for _, m := range modules {
		m.Register(r, d)
	}
}
