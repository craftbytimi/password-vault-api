package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/argon2"
)

// GenerateSalt returns a securely generated random salt of the given length.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

// DeriveKEK derives a Key Encryption Key (KEK) from the master password and salt using Argon2id.
func DeriveKEK(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// GenerateDEK generates a random Data Encryption Key (DEK).
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	return dek, err
}

// EncryptDEK encrypts the DEK with the KEK using AES-GCM (envelope encryption).
func EncryptDEK(dek, kek []byte) (nonce, encryptedDEK []byte, err error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	encryptedDEK = aesgcm.Seal(nil, nonce, dek, nil)
	return nonce, encryptedDEK, nil
}

// DecryptDEK decrypts the encrypted DEK with the KEK.
func DecryptDEK(nonce, encryptedDEK, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	dek, err := aesgcm.Open(nil, nonce, encryptedDEK, nil)
	if err != nil {
		return nil, err
	}
	return dek, nil
}

// EncryptData encrypts data with the DEK using AES-GCM.
func EncryptData(data, dek []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aesgcm.Seal(nil, nonce, data, nil)
	return nonce, ciphertext, nil
}

// DecryptData decrypts data with the DEK using AES-GCM.
func DecryptData(nonce, ciphertext, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
