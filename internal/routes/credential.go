package routes

import (
	"github.com/craftbytimi/password-vault-api/internal/handlers"
	"github.com/gin-gonic/gin"
)

func RegisterCredentialRoutes(r *gin.Engine) {
	authorized := r.Group("/")
	authorized.Use(handlers.AuthMiddleware())

	authorized.POST("/vault", handlers.CreateCredentialHandler)
	authorized.GET("/vault", handlers.ListCredentialsHandler)
	authorized.GET("/vault/search", handlers.SearchCredentialsHandler)
	authorized.PUT("/vault/:id", handlers.UpdateCredentialHandler)
	authorized.DELETE("/vault/:id", handlers.DeleteCredentialHandler)

	cred := authorized.Group("/credentials")
	cred.POST("/create", handlers.CreateCredentialHandler)
	cred.POST("/read", handlers.ReadCredentialHandler)
	cred.POST("/update", handlers.UpdateCredentialHandler)
	cred.POST("/delete", handlers.DeleteCredentialHandler)
	cred.POST("/search", handlers.SearchCredentialsHandler)
}
