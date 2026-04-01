package main

import (
	"github.com/craftbytimi/password-vault-api/internal/config"
	"github.com/craftbytimi/password-vault-api/internal/handlers"
	"github.com/craftbytimi/password-vault-api/internal/models"
	"github.com/craftbytimi/password-vault-api/internal/routes"
	"github.com/gin-gonic/gin"
)

func main() {
	// load the db connection
	db, err := config.ConnectDB()
	if err != nil {
		panic("Failed to connect to database: " + err.Error())
	}

	if err := db.AutoMigrate(&models.User{}, &models.Credential{}); err != nil {
		panic("Failed to migrate database: " + err.Error())
	}

	// gin router instance
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Password Vault API is running"})
	})

	r.POST("/register", handlers.RegisterHandler)
	r.POST("/login", handlers.LoginHandler)
	routes.RegisterCredentialRoutes(r)

	if err := r.Run(":8080"); err != nil {
		panic("Failed to start server: " + err.Error())
	}
}
