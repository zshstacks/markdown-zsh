package helpers

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secret := []byte(os.Getenv("JWT_SECRET"))

	return token.SignedString(secret)
}
