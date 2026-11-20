// Package router wires the users, auth and RBAC modules and mounts their
// routes. It opens nothing; the caller passes in every connection.
package router

import (
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Mount registers every module's routes on r and returns every module's error,
// joined. Call it once per group: gin panics on duplicate routes.
func Mount(r gin.IRouter, d module.Deps) error {
	var errs []error
	for _, m := range modules {
		if err := m.Register(r, d); err != nil {
			errs = append(errs, fmt.Errorf("authkit: mount %s: %w", m.Name, err))
		}
	}
	return errors.Join(errs...)
}
