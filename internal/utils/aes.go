package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/scrypt"
)

// derive a key from the password using a key derivation function (e.g., PBKDF2, scrypt, or Argon2)
// use the derived key to encrypt the data using AES-GCM
// return the encrypted data (including the nonce) as a base64-encoded string

func DecryptAES(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func EncryptAES(plaintext []byte, password string) ([]byte, []byte, error) {
	// derive a key from the password using a key derivation function (e.g., PBKDF2, scrypt, or Argon2)
	// For demonstration, we'll use SHA-256 hash of the password as the key

	key, err := DeriveKey([]byte(password), []byte("some_salt"))
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, iv, nil
}

func DeriveKey(password, salt []byte) ([]byte, error) {

	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32) // N=32768, r=8, p=1, key length=32 bytes
	if err != nil {
		return nil, err
	}
	return key, nil
}
