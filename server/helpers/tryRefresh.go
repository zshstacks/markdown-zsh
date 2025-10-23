package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/zshstacks/markdown-zsh/config"
	"github.com/zshstacks/markdown-zsh/initializers"
	"github.com/zshstacks/markdown-zsh/models"
)

func TryRefresh(c echo.Context) (claims *JWTClaims, err error) {

	cookie, err := c.Cookie("refresh_token")
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Refresh token missing")
	}

	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid refresh token format")
	}

	tokenID := parts[0]
	secret := parts[1]

	var refresh models.RefreshToken
	result := initializers.DB.Preload("User").First(&refresh, "token_id = ?", tokenID)
	if result.Error != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Refresh token not found")
	}

	hash := sha256.Sum256([]byte(secret))
	hashStr := hex.EncodeToString(hash[:])

	if hashStr != refresh.TokenHash {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid refresh token")
	}

	if time.Now().After(refresh.ExpiresAt) || refresh.RevokedAt != nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Refresh token is expired or revoked")
	}

	user := refresh.User

	newTokenID := uuid.NewString()
	newSecret := uuid.NewString()
	newHash := sha256.Sum256([]byte(newSecret))
	newHashStr := hex.EncodeToString(newHash[:])

	newRefresh := models.RefreshToken{
		TokenId:   newTokenID,
		TokenHash: newHashStr,
		UserID:    user.ID,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(config.App.JWT.RefreshTokenTTL) * 24 * time.Hour),
	}

	if err := initializers.DB.Create(&newRefresh).Error; err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "Failed to create a new refresh token")
	}

	now := time.Now()
	refresh.RevokedAt = &now
	refresh.ReplacedBy = &newTokenID
	initializers.DB.Save(&refresh)

	accessToken, err := SignJWT(user)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusInternalServerError, "Failed to create access token")
	}

	c.SetCookie(&http.Cookie{
		Name:     "token",
		Value:    accessToken,
		Path:     "/",
		MaxAge:   config.App.JWT.AccessTokenTTL * 60,
		HttpOnly: true,
		Secure:   config.App.Cookie.Secure,
		SameSite: config.App.Cookie.SameSite,
	})

	c.SetCookie(&http.Cookie{
		Name:     "refresh_token",
		Value:    newTokenID + "." + newSecret,
		Path:     "/",
		MaxAge:   config.App.JWT.RefreshTokenTTL * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   config.App.Cookie.Secure,
		SameSite: config.App.Cookie.SameSite,
	})

	claims = &JWTClaims{
		Sub: user.ID,
		UID: user.UniqueID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(config.App.JWT.AccessTokenTTL) * time.Minute)),
		},
	}

	return claims, nil
}
