package routes

import (
	"github.com/labstack/echo/v4"
	"github.com/zshstacks/markdown-zsh/controllers"
	"github.com/zshstacks/markdown-zsh/middleware"
)

func AuthRoutes(e *echo.Echo) {
	Public := e.Group("/")
	{
		Public.POST("register", controllers.Register)
		Public.POST("login", controllers.Login)
		Public.POST("auth/refresh", controllers.Refresh)
		Public.POST("auth/refresh/logout", controllers.Logout)
	}

	Private := e.Group("/user")
	Private.Use(middleware.RequireAuth)
	{
		Private.GET("/current", controllers.GetCurrentUser)
	}

}
