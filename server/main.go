package main

import (
	"fmt"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/zshstacks/markdown-zsh/config"
	"github.com/zshstacks/markdown-zsh/initializers"
	"github.com/zshstacks/markdown-zsh/routes"
)

func init() {
	initializers.LoadEnvVariables()
	config.Init()
	initializers.ConnectToDB()
	initializers.SyncDatabase()

}

func main() {
	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.Secure())

	routes.AuthRoutes(e)

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     config.App.CORS.AllowedOrigins,
		AllowMethods:     config.App.CORS.AllowedMethods,
		AllowHeaders:     config.App.CORS.AllowedHeaders,
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           int((24 * time.Hour) / time.Millisecond),
	}))

	e.Server.ReadTimeout = time.Duration(config.App.Server.ReadTimeout) * time.Second
	e.Server.WriteTimeout = time.Duration(config.App.Server.WriteTimeout) * time.Second

	port := fmt.Sprintf(":%s", config.App.Server.Port)

	e.Logger.Fatal(e.Start(port))
}
