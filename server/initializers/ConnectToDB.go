package initializers

import (
	"fmt"

	"github.com/zshstacks/markdown-zsh/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectToDB() {
	var err error

	dbHost := config.App.Database.Host
	dbPort := config.App.Database.Port
	dbName := config.App.Database.Name
	dbUser := config.App.Database.User
	dbPassword := config.App.Database.Password

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", dbHost, dbUser, dbPassword, dbName, dbPort)

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic(err.Error())
	}

	fmt.Println("Connected to database successfully")
}
