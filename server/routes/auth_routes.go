package routes

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func AuthRoutes(e *echo.Echo) {
	AuthGroup := e.Group("/")
	{
		AuthGroup.GET("logout", func(c echo.Context) error { return c.String(http.StatusOK, "logout") })
	}

}
