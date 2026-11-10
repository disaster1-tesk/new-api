package router

import (
	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"

	"github.com/gin-gonic/gin"
)

// registerAuthzRoleRoutes mounts custom role management, which only the root
// user may use.
func registerAuthzRoleRoutes(apiRouter *gin.RouterGroup) {
	roleRoute := apiRouter.Group("/authz")
	roleRoute.Use(middleware.RootAuth())
	{
		roleRoute.GET("/roles", controller.ListAuthzRoles)
		roleRoute.POST("/roles", controller.CreateAuthzRole)
		roleRoute.PUT("/roles/:key", controller.UpdateAuthzRole)
		roleRoute.DELETE("/roles/:key", controller.DeleteAuthzRole)
		roleRoute.GET("/roles/:key/members", controller.GetAuthzRoleMembers)
		roleRoute.PUT("/roles/:key/members", controller.SetAuthzRoleMembers)
		roleRoute.GET("/users/:id/roles", controller.GetAuthzUserRoles)
		roleRoute.PUT("/users/:id/roles", controller.SetAuthzUserRoles)
	}
}
