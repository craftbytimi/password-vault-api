package main

import (
	"github.com/craftbytimi/password-vault-api/internal/config"
	"github.com/gin-gonic/gin"
)

func main() {
	// load the db connection
	config.ConnectDB()

	// gin router instance
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.String(200, "Hello, World!")
	})

	r.Run(":8080")
}

