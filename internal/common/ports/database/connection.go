package database

import (
	"context"
	"database/sql"
)

// DBConfig is the configuration for the database
type DBConfig struct {
	ConnectionString string
}

// Connection represents a database connection interface
type Connection interface {
	// Connect establishes a connection to the database
	Connect(ctx context.Context) (*sql.DB, error)
	// Close closes the database connection
	Close() error
	// Ping pings the database
	Ping(ctx context.Context) error
	// SeedDB seeds the database
	SeedDB(ctx context.Context) error
}
