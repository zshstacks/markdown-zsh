package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UniqueID              string `gorm:"uniqueIndex;size:12"`
	Email                 string `gorm:"unique"`
	Username              string
	Password              string
	IsEmailConfirmed      bool
	EmailConfirmationCode string
}
