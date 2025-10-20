package controllers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/zshstacks/markdown-zsh/helpers"
	"github.com/zshstacks/markdown-zsh/initializers"
	"github.com/zshstacks/markdown-zsh/models"
	"golang.org/x/crypto/bcrypt"
)

func Login(c echo.Context) error {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read body")
	}

	user, err := helpers.FindUserByEmail(body.Email)
	if err != nil || user.ID == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid email or password")
	}

	accessToken, err := helpers.SignJWT(user)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create access token")
	}

	c.SetCookie(&http.Cookie{
		Name:     "token",
		Value:    accessToken,
		Path:     "/",
		MaxAge:   15 * 60,
		HttpOnly: true,
		Secure:   false, //  true in production HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	//create refresh token
	tokenID := uuid.NewString()
	secret := uuid.NewString()

	hash := sha256.Sum256([]byte(secret))
	hashStr := hex.EncodeToString(hash[:])

	refresh := models.RefreshToken{
		TokenId:   tokenID,
		TokenHash: hashStr,
		UserID:    user.ID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	if err := initializers.DB.Create(&refresh).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save refresh token")
	}

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    tokenID + "." + secret,
		Path:     "/auth/refresh",
		MaxAge:   7 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	resp := struct {
		ID       uint   `json:"id"`
		UniqueID string `json:"unique_id"`
		Email    string `json:"email"`
		Username string `json:"username"`
	}{
		ID:       user.ID,
		UniqueID: user.UniqueID,
		Email:    user.Email,
		Username: user.Username,
	}

	return c.JSON(http.StatusOK, resp)
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
					return echo.NewHTTPError(http.StatusInternalServerError, "failed to create user due to id collision, try again")
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
