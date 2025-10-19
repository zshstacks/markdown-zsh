package controllers

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/zshstacks/markdown-zsh/helpers"
	"github.com/zshstacks/markdown-zsh/initializers"
	"github.com/zshstacks/markdown-zsh/models"
	"golang.org/x/crypto/bcrypt"
)

func Login(c echo.Context) error {
	return c.String(http.StatusOK, "login")
}

func Register(c echo.Context) error {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Username string `json:"username"`
	}

	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read body")
	}

	if body.Email == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email is required!")
	}

	if body.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Password is required!")
	}

	if body.Username == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required!")
	}

	if len(body.Password) < 8 {
		return echo.NewHTTPError(http.StatusBadRequest, "Password must be at least 8 characters long")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to hash password")
	}

	user := models.User{
		Email:    body.Email,
		Password: string(hash),
		Username: body.Username,
	}

	const maxAttempts = 5
	var created bool
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		u, err := helpers.GenerateUniqueID(12)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate unique id")
		}
		user.UniqueID = u

		if err := initializers.DB.Create(&user).Error; err != nil {
			// treat DB unique constraint on email or uniqueid as a retryable collision
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
				if attempt == maxAttempts {
					return echo.NewHTTPError(http.StatusInternalServerError, "failed to create user due to id collision; try again")
				}
				continue
			}
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to create user")
		}
		created = true
		break
	}

	if !created {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create user")
	}

	//dto for safe response
	resp := struct {
		ID        uint      `json:"id"`
		UniqueID  string    `json:"unique_id"`
		Email     string    `json:"email"`
		Username  string    `json:"username"`
		CreatedAt time.Time `json:"created_at"`
	}{
		ID:        user.ID,
		UniqueID:  user.UniqueID,
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
	}

	return c.JSON(http.StatusOK, resp)
}

func Logout(c echo.Context) error {
	return c.String(http.StatusOK, "logout")
}
