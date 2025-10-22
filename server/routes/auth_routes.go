package routes

import (
	"github.com/labstack/echo/v4"
	"github.com/zshstacks/markdown-zsh/controllers"
)

func AuthRoutes(e *echo.Echo) {
	Public := e.Group("/")
	{
		Public.POST("register", controllers.Register)
		Public.POST("login", controllers.Login)
		Public.POST("auth/refresh", controllers.Refresh)
		Public.POST("auth/refresh/logout", controllers.Logout)
	}

}
