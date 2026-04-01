package models

import (
	"fmt"
	"time"
)

type User struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Username       string    `gorm:"uniqueIndex;not null" json:"username"`
	HashedPassword string    `gorm:"not null" json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
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
	if u.HashedPassword == "" {
		return fmt.Errorf("hashed password is required")
	}
	return nil
}
