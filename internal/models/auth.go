package models

import (
	"fmt"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID             uint                        `gorm:"primaryKey" json:"id"`
	Username       string                      `gorm:"unique" json:"username"`
	Password       string                      `json:"password"`
	HashedPassword string                      `json:"hash"`
	SetPassword    func(password string) error `gorm:"-" json:"-"`
}

type UserLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserRegister struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// validate the user input for registration and login
func (u *User) Validate() error {
	if u.Username == "" {
		return fmt.Errorf("username is required")
	}
	if u.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
