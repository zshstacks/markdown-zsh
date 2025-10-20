package helpers

import (
	"github.com/zshstacks/markdown-zsh/initializers"
	"github.com/zshstacks/markdown-zsh/models"
)

func FindUserByEmail(email string) (models.User, error) {
	var user models.User

	if err := initializers.DB.First(&user, "email = ?", email).Error; err != nil {
		return user, err
	}

	return user, nil
}
