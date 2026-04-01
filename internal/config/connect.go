package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	dbInstance *gorm.DB
	envOnce    sync.Once
)

// ConnectDB establishes a connection to the PostgreSQL database
// It loads environment variables from .env file and creates a GORM DB instance
// Returns the database connection and any error encountered
func ConnectDB() (*gorm.DB, error) {
	loadEnv()

	// Get database connection string from environment variable
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}

	// Create database connection using GORM with PostgreSQL driver
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	fmt.Println("Database connection is established")
	dbInstance = db

	// Return successful database connection
	return db, nil
}

func GetDB() *gorm.DB {
	return dbInstance
}

func loadEnv() {
	envOnce.Do(func() {
		if err := godotenv.Load(".env"); err != nil {
			log.Printf("warning: could not load .env file: %v", err)
		}
	})
}
