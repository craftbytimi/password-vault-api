package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/craftbytimi/password-vault-api/internal/config"
	"github.com/craftbytimi/password-vault-api/internal/models"
	"github.com/craftbytimi/password-vault-api/internal/utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type createCredentialRequest struct {
	Name           string `json:"name" binding:"required"`
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	MasterPassword string `json:"master_password" binding:"required"`
}

type readCredentialRequest struct {
	CredentialID   uint   `json:"credential_id" binding:"required"`
	MasterPassword string `json:"master_password" binding:"required"`
}

type updateCredentialRequest struct {
	CredentialID   uint   `json:"credential_id"`
	Name           string `json:"name"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	MasterPassword string `json:"master_password"`
}

type deleteCredentialRequest struct {
	CredentialID uint `json:"credential_id"`
}

type searchCredentialRequest struct {
	Query string `json:"query"`
}

// CreateCredentialHandler handles creation of a new credential.
func CreateCredentialHandler(c *gin.Context) {
	var req createCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	user, ok := CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
		return
	}

	db := config.GetDB()
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database is not configured"})
		return
	}

	salt, err := utils.GenerateSalt(16)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate salt"})
		return
	}

	kek := utils.DeriveKEK(req.MasterPassword, salt)
	dek, err := utils.GenerateDEK()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate data encryption key"})
		return
	}

	dekNonce, encryptedDEK, err := utils.EncryptDEK(dek, kek)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt data encryption key"})
		return
	}

	dataNonce, encryptedPassword, err := utils.EncryptData([]byte(req.Password), dek)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt credential"})
		return
	}

	credential := models.Credential{
		UserID:            user.ID,
		Name:              req.Name,
		Username:          req.Username,
		Salt:              salt,
		EncryptedPassword: encryptedPassword,
		EncryptedDEK:      encryptedDEK,
		DEKNonce:          dekNonce,
		DataNonce:         dataNonce,
	}
	if err := db.Create(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save credential"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":    "credential created successfully",
		"credential": credentialSummary(credential),
	})
}

// ListCredentialsHandler returns all credentials for the authenticated user.
func ListCredentialsHandler(c *gin.Context) {
	user, ok := CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
		return
	}

	db := config.GetDB()
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database is not configured"})
		return
	}

	var credentials []models.Credential
	if err := db.Where("user_id = ?", user.ID).Order("created_at DESC").Find(&credentials).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"credentials": summarizeCredentials(credentials)})
}

// ReadCredentialHandler fetches and decrypts a credential.
func ReadCredentialHandler(c *gin.Context) {
	var req readCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	user, ok := CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
		return
	}

	db := config.GetDB()
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database is not configured"})
		return
	}

	credential, err := findCredentialByOwner(db, user.ID, req.CredentialID)
	if err != nil {
		respondCredentialLookupError(c, err)
		return
	}

	password, err := decryptCredentialPassword(credential, req.MasterPassword)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid master password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"credential": gin.H{
			"id":         credential.ID,
			"name":       credential.Name,
			"username":   credential.Username,
			"password":   password,
			"created_at": credential.CreatedAt,
			"updated_at": credential.UpdatedAt,
		},
	})
}

// UpdateCredentialHandler updates a credential and re-encrypts the password when provided.
func UpdateCredentialHandler(c *gin.Context) {
	var req updateCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
		return
	}

	user, ok := CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
		return
	}

	id, ok := credentialIDFromRequest(c, req.CredentialID)
	if !ok {
		return
	}

	db := config.GetDB()
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database is not configured"})
		return
	}

	credential, err := findCredentialByOwner(db, user.ID, id)
	if err != nil {
		respondCredentialLookupError(c, err)
		return
	}

	if req.Name != "" {
		credential.Name = req.Name
	}
	if req.Username != "" {
		credential.Username = req.Username
	}
	if req.Password != "" {
		if req.MasterPassword == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "master_password is required when updating password"})
			return
		}

		kek := utils.DeriveKEK(req.MasterPassword, credential.Salt)
		dek, err := utils.DecryptDEK(credential.DEKNonce, credential.EncryptedDEK, kek)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid master password"})
			return
		}

		dataNonce, encryptedPassword, err := utils.EncryptData([]byte(req.Password), dek)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt credential"})
			return
		}

		credential.DataNonce = dataNonce
		credential.EncryptedPassword = encryptedPassword
	}

	if err := db.Save(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update credential"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "credential updated successfully",
		"credential": credentialSummary(credential),
	})
}

// DeleteCredentialHandler deletes a credential.
func DeleteCredentialHandler(c *gin.Context) {
	var req deleteCredentialRequest
	if c.Param("id") == "" {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
			return
		}
	}

	user, ok := CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
		return
	}

	id, ok := credentialIDFromRequest(c, req.CredentialID)
	if !ok {
		return
	}

	db := config.GetDB()
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database is not configured"})
		return
	}

	result := db.Where("id = ? AND user_id = ?", id, user.ID).Delete(&models.Credential{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete credential"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "credential deleted successfully"})
}

// SearchCredentialsHandler searches credentials by name or username.
func SearchCredentialsHandler(c *gin.Context) {
	user, ok := CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
		return
	}

	query := strings.TrimSpace(c.Query("q"))
	if query == "" {
		if c.Request.Method == http.MethodGet {
			c.JSON(http.StatusBadRequest, gin.H{"error": "query is required"})
			return
		}

		var req searchCredentialRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid input"})
			return
		}
		query = strings.TrimSpace(req.Query)
	}

	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query is required"})
		return
	}

	db := config.GetDB()
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database is not configured"})
		return
	}

	pattern := "%" + query + "%"
	var results []models.Credential
	if err := db.Where(
		"user_id = ? AND (name ILIKE ? OR username ILIKE ?)",
		user.ID,
		pattern,
		pattern,
	).Order("created_at DESC").Find(&results).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to search credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": summarizeCredentials(results)})
}

func credentialSummary(credential models.Credential) gin.H {
	return gin.H{
		"id":         credential.ID,
		"name":       credential.Name,
		"username":   credential.Username,
		"created_at": credential.CreatedAt,
		"updated_at": credential.UpdatedAt,
	}
}

func summarizeCredentials(credentials []models.Credential) []gin.H {
	results := make([]gin.H, 0, len(credentials))
	for _, credential := range credentials {
		results = append(results, credentialSummary(credential))
	}
	return results
}

func credentialIDFromRequest(c *gin.Context, bodyID uint) (uint, bool) {
	if pathID := c.Param("id"); pathID != "" {
		value, err := strconv.ParseUint(pathID, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
			return 0, false
		}
		return uint(value), true
	}

	if bodyID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "credential_id is required"})
		return 0, false
	}

	return bodyID, true
}

func findCredentialByOwner(db *gorm.DB, userID, credentialID uint) (models.Credential, error) {
	var credential models.Credential
	err := db.Where("id = ? AND user_id = ?", credentialID, userID).First(&credential).Error
	return credential, err
}

func respondCredentialLookupError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch credential"})
}

func decryptCredentialPassword(credential models.Credential, masterPassword string) (string, error) {
	kek := utils.DeriveKEK(masterPassword, credential.Salt)
	dek, err := utils.DecryptDEK(credential.DEKNonce, credential.EncryptedDEK, kek)
	if err != nil {
		return "", err
	}

	password, err := utils.DecryptData(credential.DataNonce, credential.EncryptedPassword, dek)
	if err != nil {
		return "", err
	}

	return string(password), nil
}
