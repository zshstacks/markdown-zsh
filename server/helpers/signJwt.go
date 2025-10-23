package helpers

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zshstacks/markdown-zsh/config"
	"github.com/zshstacks/markdown-zsh/models"
)

type JWTClaims struct {
	Sub uint   `json:"sub"`
	UID string `json:"uid"`
	jwt.RegisteredClaims
}

func SignJWT(user models.User) (string, error) {
	claims := JWTClaims{
		Sub: user.ID,
		UID: user.UniqueID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(
				time.Now().Add(time.Duration(config.App.JWT.AccessTokenTTL) * time.Minute),
			),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := []byte(os.Getenv(config.App.JWT.Secret))

	return token.SignedString(secret)
}
