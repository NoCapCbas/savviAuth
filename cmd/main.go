package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	savviHttp "savviAuth/internal/adapters/http"
	"savviAuth/internal/adapters/postgres"
	"savviAuth/internal/auth"
	"savviAuth/internal/common/ports/database"
	"savviAuth/internal/users"
)

func main() {
	// get env variables
	env := os.Getenv("ENV")

	// database connection
	DB_USER := os.Getenv("DB_USER")
	DB_PASSWORD := os.Getenv("DB_PASSWORD")
	DB_NAME := os.Getenv("DB_NAME")
	dsn := fmt.Sprintf("postgres://%s:%s@db:5432/%s?sslmode=disable", DB_USER, DB_PASSWORD, DB_NAME)
	dbConfig := database.DBConfig{
		ConnectionString: dsn,
	}
	dbConn := postgres.NewPostgresConnection(dbConfig)
	ctx := context.Background()
	db, err := dbConn.Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// init user repo
	userRepo, err := postgres.NewUserRepository(db, env)
	if err != nil {
		log.Fatalf("Failed to initialize user repository: %v", err)
	}

	// init user service
	userService := users.NewUserService(userRepo)
	// init auth service
	authService := auth.NewAuthService()

	if env == "dev" {
		log.Println("Running in dev mode")
	} else {
		log.Println("Running in prod mode")
	}
	// hello world server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Hello, World!")
		fmt.Fprintf(w, "Hello, World!")
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Health check")
		fmt.Fprintf(w, "OK")
	})

	// pass user service to handler
	userHandler := savviHttp.NewUserHandler(userService)
	userHandler.RegisterRoutes()

	// pass auth service to handler
	authHandler := savviHttp.NewAuthHandler(authService)
	authHandler.RegisterRoutes()

	// start server
	log.Println("Server is running on port 8080")
	http.ListenAndServe(":8080", nil)
}
