package models

// Credential represents a user's stored credential (e.g., password, note, etc.)
type Credential struct {
	ID                uint   `gorm:"primaryKey" json:"id"`
	UserID            uint   `gorm:"index;not null" json:"user_id"`
	Name              string `gorm:"not null" json:"name"`
	Username          string `gorm:"not null" json:"username"`
	Salt              []byte `gorm:"not null" json:"-"`
	EncryptedPassword []byte `gorm:"not null" json:"-"`
	EncryptedDEK      []byte `gorm:"not null" json:"-"`
	DEKNonce          []byte `gorm:"not null" json:"-"`
	DataNonce         []byte `gorm:"not null" json:"-"`
	CreatedAt         int64  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt         int64  `gorm:"autoUpdateTime" json:"updated_at"`
}
