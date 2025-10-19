package models

import "time"

type RefreshToken struct {
	ID         uint       `gorm:"primaryKey"`
	TokenId    string     `gorm:"size:36;uniqueIndex;not null"`
	TokenHash  string     `gorm:"size:64;index;not null"`
	UserID     uint       `gorm:"index;not null"`
	IssuedAt   time.Time  `gorm:"not null"`
	ExpiresAt  time.Time  `gorm:"not null"`
	RevokedAt  *time.Time `gorm:"index;default:null"`
	ReplacedBy *string    `gorm:"size:36;index;default:null"`
	Device     *string    `gorm:"size:255;default:null"`
	IP         *string    `gorm:"size:45;default:null"`
	UserAgent  *string    `gorm:"type:text;default:null"`
	LastUsedAt *time.Time `gorm:"index;default:null"`

	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
}
