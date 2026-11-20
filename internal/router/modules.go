package router

import (
	routerappconfig "github.com/zazhedho/authkit/internal/router/appconfig"
	routeraudit "github.com/zazhedho/authkit/internal/router/audit"
	routermenu "github.com/zazhedho/authkit/internal/router/menu"
	"github.com/zazhedho/authkit/internal/router/module"
	routerpermission "github.com/zazhedho/authkit/internal/router/permission"
	routerrole "github.com/zazhedho/authkit/internal/router/role"
	routersession "github.com/zazhedho/authkit/internal/router/session"
	routeruser "github.com/zazhedho/authkit/internal/router/user"
)

// modules is every module Mount registers, in alphabetical order. Adding a
// module is one line here; the route table test pins its routes.
var modules = []module.Entry{
	{Name: "appconfig", Register: routerappconfig.Register},
	{Name: "audit", Register: routeraudit.Register},
	{Name: "menu", Register: routermenu.Register},
	{Name: "permission", Register: routerpermission.Register},
	{Name: "role", Register: routerrole.Register},
	{Name: "session", Register: routersession.Register},
	{Name: "user", Register: routeruser.Register},
}
