package main

import (
	"github.com/craftbytimi/password-vault-api/internal/config"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var dbInstance *gorm.DB

func main() {
	// load the db connection
	db, err := config.ConnectDB()
	if err != nil {
		panic("Failed to connect to database: " + err.Error())
	}
	dbInstance = db

	// gin router instance
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.String(200, "Hello, World!")
	})

	r.Run(":8080")
}
