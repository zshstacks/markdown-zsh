package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func Login(c echo.Context) error {
	return c.String(http.StatusOK, "login")
}

func Register(c echo.Context) error {
	return c.String(http.StatusOK, "register")
}

func Logout(c echo.Context) error {
	return c.String(http.StatusOK, "logout")
}
