package routes

import (
	"github.com/craftbytimi/password-vault-api/internal/handlers"
	"github.com/gin-gonic/gin"
)

func RegisterCredentialRoutes(r *gin.Engine) {
	cred := r.Group("/credentials")
	cred.POST("/create", handlers.CreateCredentialHandler)
	cred.POST("/read", handlers.ReadCredentialHandler)
	cred.POST("/update", handlers.UpdateCredentialHandler)
	cred.POST("/delete", handlers.DeleteCredentialHandler)
	cred.POST("/search", handlers.SearchCredentialsHandler)
}
