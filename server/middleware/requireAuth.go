package middleware

import (
	"errors"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/zshstacks/markdown-zsh/helpers"
	"github.com/zshstacks/markdown-zsh/initializers"
	"github.com/zshstacks/markdown-zsh/models"
)

func getAccessTokenFromRequest(c echo.Context) (string, error) {
	cookie, err := c.Cookie("token")
	if err != nil {
		return "", echo.NewHTTPError(http.StatusUnauthorized, "Token is missing")
	}
	return cookie.Value, nil
}

// this is from error handling section in echo docs
func RequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {

		tokenStr, err := getAccessTokenFromRequest(c)
		if err != nil {
			return err
		}

		claims, err := helpers.VerifyAccessToken(tokenStr)
		if err != nil {
			// check if error is due to expired token
			if errors.Is(err, jwt.ErrTokenExpired) {
				// token expired ,try refresh
				claims, err = helpers.TryRefresh(c)
				if err != nil {
					return err
				}
			} else {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
			}
		}

		user := models.User{}
		initializers.DB.First(&user, claims.Sub)
		if user.ID == 0 {
			return echo.NewHTTPError(http.StatusUnauthorized, "User not found")
		}

		c.Set("user", user)
		return next(c)
	}
}
