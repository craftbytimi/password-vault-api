package models

// Credential represents a user's stored credential (e.g., password, note, etc.)
type Credential struct {
	ID                uint `gorm:"primaryKey"`
	UserID            uint // Foreign key to User
	Name              string
	Username          string
	EncryptedPassword []byte // Encrypted credential
	EncryptedDEK      []byte // Envelope-encrypted DEK
	DEKNonce          []byte // Nonce used for DEK encryption
	DataNonce         []byte // Nonce used for credential encryption
	CreatedAt         int64
	UpdatedAt         int64
}
