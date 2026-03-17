package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ConnectDB establishes a connection to the PostgreSQL database
// It loads environment variables from .env file and creates a GORM DB instance
// Returns the database connection and any error encountered
func ConnectDB() (*gorm.DB, error) {
	// Load environment variables from .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading the .env file %s", err)
	}

	// Get database connection string from environment variable
	dsn := os.Getenv("DATABASE_URL")

	// Create database connection using GORM with PostgreSQL driver
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	fmt.Println("Database connection is established")

	// Return successful database connection
	return db, nil
}
