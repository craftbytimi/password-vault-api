package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	ID             uint                        `gorm:"primaryKey" json:"id"`
	Username       string                      `gorm:"unique" json:"username"`
	Password       string                      `json:"password"`
	HashedPassword string                      `json:"hash"`
	SetPassword    func(password string) error `gorm:"-" json:"-"`
}
