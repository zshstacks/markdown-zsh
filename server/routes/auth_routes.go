package routes

import (
	"github.com/labstack/echo/v4"
	"github.com/zshstacks/markdown-zsh/controllers"
)

func AuthRoutes(e *echo.Echo) {
	AuthGroup := e.Group("/")
	{
		AuthGroup.POST("register", controllers.Register)
	}

}
