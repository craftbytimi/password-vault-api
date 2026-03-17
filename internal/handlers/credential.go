package handlers

import (
	"net/http"
	"time"

	"github.com/craftbytimi/password-vault-api/internal/models"
	"github.com/craftbytimi/password-vault-api/internal/utils"
	"github.com/gin-gonic/gin"
)

// CreateCredentialHandler handles creation of a new credential
func CreateCredentialHandler(c *gin.Context) {
	var req struct {
		Name           string `json:"name" binding:"required"`
		Username       string `json:"username" binding:"required"`
		Password       string `json:"password" binding:"required"`
		MasterPassword string `json:"master_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	userID := uint(1) // TODO: Get user ID from JWT claims
	salt, err := utils.GenerateSalt(16)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate salt"})
		return
	}
	kek := utils.DeriveKEK(req.MasterPassword, salt)
	dek, err := utils.GenerateDEK()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate DEK"})
		return
	}
	dekNonce, encryptedDEK, err := utils.EncryptDEK(dek, kek)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt DEK"})
		return
	}
	dataNonce, encryptedPassword, err := utils.EncryptData([]byte(req.Password), dek)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credential"})
		return
	}
	_ = models.Credential{
		UserID:            userID,
		Name:              req.Name,
		Username:          req.Username,
		EncryptedPassword: encryptedPassword,
		EncryptedDEK:      encryptedDEK,
		DEKNonce:          dekNonce,
		DataNonce:         dataNonce,
		CreatedAt:         time.Now().Unix(),
		UpdatedAt:         time.Now().Unix(),
	}
	// TODO: Save salt with user record
	// TODO: Save credential to DB
	c.JSON(http.StatusOK, gin.H{"message": "Credential created successfully"})
}

// ReadCredentialHandler fetches and decrypts a credential
func ReadCredentialHandler(c *gin.Context) {
	var req struct {
		CredentialID   uint   `json:"credential_id" binding:"required"`
		MasterPassword string `json:"master_password" binding:"required"`
		Salt           []byte `json:"salt" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	// TODO: Fetch credential from DB by req.CredentialID and userID
	// credential := models.Credential{} // Placeholder
	// Placeholder for DB fetch and decrypt logic
	// Fetch credential from DB and use its fields for decryption
	c.JSON(http.StatusOK, gin.H{"message": "Fetch and decrypt credential logic goes here"})
}

// UpdateCredentialHandler updates and re-encrypts a credential
func UpdateCredentialHandler(c *gin.Context) {
	var req struct {
		CredentialID   uint   `json:"credential_id" binding:"required"`
		Name           string `json:"name"`
		Username       string `json:"username"`
		Password       string `json:"password"`
		MasterPassword string `json:"master_password" binding:"required"`
		Salt           []byte `json:"salt" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	// TODO: Fetch credential from DB by req.CredentialID and userID
	// credential := models.Credential{} // Placeholder
	// Placeholder for DB fetch and update logic
	// dekNonce, encryptedDEK, err := utils.EncryptDEK(dek, kek)
	// if err != nil {
	//     c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt DEK"})
	//     return
	// }
	// dataNonce, encryptedPassword, err := utils.EncryptData([]byte(req.Password), dek)
	// if err != nil {
	//     c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credential"})
	//     return
	// }
	// TODO: Update credential fields and save to DB
	c.JSON(http.StatusOK, gin.H{"message": "Credential updated successfully"})
}

// DeleteCredentialHandler deletes a credential
func DeleteCredentialHandler(c *gin.Context) {
	var req struct {
		CredentialID uint `json:"credential_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	// TODO: Delete credential from DB by req.CredentialID and userID
	c.JSON(http.StatusOK, gin.H{"message": "Credential deleted successfully"})
}

// SearchCredentialsHandler searches credentials by name or username
func SearchCredentialsHandler(c *gin.Context) {
	var req struct {
		Query string `json:"query" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	// TODO: Search credentials in DB for userID matching req.Query
	results := []models.Credential{} // Placeholder
	c.JSON(http.StatusOK, gin.H{"results": results})
}
