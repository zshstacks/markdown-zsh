package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UniqueID              string `gorm:"uniqueIndex;size:12;not null"`
	Email                 string `gorm:"uniqueIndex;size:40;not null"`
	Username              string `gorm:"size:30"`
	Password              string `gorm:"not null"`
	IsEmailConfirmed      bool   `gorm:"default:false"`
	EmailConfirmationCode string `gorm:"size:64"`
}
