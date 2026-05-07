package main

import (
	"log"
	"os"

	"github.com/secretops/backend/internal/api"
	"github.com/secretops/backend/internal/models"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./data/secretops.db"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	db, err := models.NewDB(dbPath)
	if err != nil {
		log.Fatalf("DB init failed: %v", err)
	}
	defer db.Close()

	srv := api.NewServer(db, port)
	log.Printf("SecretOps API starting on :%s", port)
	if err := srv.Run(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
