package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

	userHttp "savviAuth/internal/adapters/http"
	"savviAuth/internal/adapters/postgres"
	"savviAuth/internal/common/ports/database"
	"savviAuth/internal/users"
)

func init() {
	env := "test"
	// init db
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

	// init repo
	userRepo, err := postgres.NewUserRepository(db, env)
	if err != nil {
		log.Fatalf("Failed to initialize user repository: %v", err)
	}

	// init service
	userService := users.NewUserService(userRepo)

	// init handler
	userHandler := userHttp.NewUserHandler(userService)
	userHandler.RegisterRoutes()
}
func TestCreateUser(t *testing.T) {

}
func TestGetUser(t *testing.T) {

}
func TestUpdateUser(t *testing.T) {

}

func TestDisableUser(t *testing.T) {

}
func TestDeleteUser(t *testing.T) {

}
func TestListUsers(t *testing.T) {

}
