package main

import (
	"log"
	"pmld/database"
	"pmld/models"
	"pmld/routes"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Connect DB
	database.ConnectDB()
	database.DB.AutoMigrate(&models.User{})

	r := gin.Default()

	// Public routes
	r.POST("/register", routes.Register)
	r.POST("/login", routes.Login)
	r.GET("/auth/google", routes.GoogleLogin)
	r.GET("/auth/google/callback", routes.GoogleCallback)

	// Protected route → langsung validasi di handler
	r.GET("/profile", routes.Profile)

	// Run server
	r.Run(":8080")
}
