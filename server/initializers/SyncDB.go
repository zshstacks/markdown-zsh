package initializers

import (
	"log"

	"github.com/zshstacks/markdown-zsh/models"
)

func SyncDatabase() {
	err := DB.AutoMigrate(models.User{})

	if err != nil {
		log.Fatalf("Database migration error: %v", err)
	} else {
		log.Println("Database migrated successfully!")
	}
}
