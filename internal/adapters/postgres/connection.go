package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"savviAuth/internal/common/ports/database"

	_ "github.com/lib/pq"
)

type PostgresConnection struct {
	config database.DBConfig
	db     *sql.DB
}

func NewPostgresConnection(config database.DBConfig) *PostgresConnection {
	return &PostgresConnection{
		config: config,
	}
}

func (p *PostgresConnection) Connect(ctx context.Context) (*sql.DB, error) {
	db, err := sql.Open("postgres", p.config.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	p.db = db
	return db, nil
}

func (p *PostgresConnection) Close() error {
	if p.db == nil {
		return fmt.Errorf("database connection is not open")
	}
	return p.db.Close()
}

func (p *PostgresConnection) Ping(ctx context.Context) error {
	if p.db == nil {
		return fmt.Errorf("database connection is not open")
	}
	return p.db.PingContext(ctx)
}

func (p *PostgresConnection) SeedDB(ctx context.Context) error {
	// create users table
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(50) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		is_admin BOOLEAN DEFAULT FALSE,
		disabled BOOLEAN DEFAULT FALSE
	)`
	_, err := p.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// create permissions table
	query = `
	CREATE TABLE IF NOT EXISTS permissions (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		user_id UUID NOT NULL,
		service VARCHAR(255) NOT NULL,
		permissions JSONB NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	)`
	return nil
}
