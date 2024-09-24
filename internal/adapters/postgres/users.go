package postgres

import (
	"database/sql"
	"errors"
	"log"
	"time"

	"savviAuth/internal/common"
	"savviAuth/internal/users"

	"github.com/google/uuid"
)

type userRepository struct {
	db *sql.DB
}

func (r *userRepository) Create(user *users.User) error {
	// check if user already exists
	query := `
		SELECT id FROM users WHERE email = $1
	`
	row := r.db.QueryRow(query, user.Email)
	var existingUser users.User
	err := row.Scan(&existingUser.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("user with email:(" + user.Email + ") does not exist")
		} else {
			return err
		}
	}
	// if user already exists, return error
	if existingUser.ID != uuid.Nil {
		return errors.New("user with email:(" + user.Email + ") already exists")
	}
	log.Println("creating user with email:(" + user.Email + ")")
	query = `
		INSERT INTO users (id, email, password_hash, created_at, updated_at, is_admin, disabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = r.db.Exec(query, user.ID, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt, user.IsAdmin, user.Disabled)
	return err
}

func (r *userRepository) GetByID(id uuid.UUID) (*users.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at, is_admin, disabled FROM users WHERE id = $1`
	return r.scanUser(r.db.QueryRow(query, id))
}

func (r *userRepository) GetByUsername(username string) (*users.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at, is_admin, disabled FROM users WHERE email = $1`
	return r.scanUser(r.db.QueryRow(query, username))
}

func (r *userRepository) GetByEmail(email string) (*users.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at, is_admin, disabled FROM users WHERE email = $1`
	return r.scanUser(r.db.QueryRow(query, email))
}

func (r *userRepository) Update(user *users.User) error {
	query := `
		UPDATE users
		SET email = $2, password_hash = $3, updated_at = $4, is_admin = $5, disabled = $6
		WHERE id = $1
	`
	_, err := r.db.Exec(query, user.ID, user.Email, user.PasswordHash, time.Now(), user.IsAdmin, user.Disabled)
	return err
}

func (r *userRepository) Delete(id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.Exec(query, id)
	return err
}

func (r *userRepository) List() ([]*users.User, error) {
	query := `SELECT id, email, password_hash, created_at, updated_at, is_admin, disabled FROM users`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*users.User
	for rows.Next() {
		user, err := r.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// scanUser scans a user from the database
func (r *userRepository) scanUser(row interface{}) (*users.User, error) {
	var user users.User
	var scanner interface {
		Scan(dest ...interface{}) error
	}

	switch v := row.(type) {
	case *sql.Row:
		scanner = v
	case *sql.Rows:
		scanner = v
	default:
		return nil, errors.New("invalid row type")
	}

	err := scanner.Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.IsAdmin,
		&user.Disabled,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// seed is a helper function to seed the database with users
func (r *userRepository) seedRepo() error {
	users := []users.User{
		{
			ID:           uuid.New(),
			Email:        "admin@example.com",
			PasswordHash: common.MustHashPassword("admin"),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			IsAdmin:      true,
			Disabled:     false,
		},
		{
			ID:           uuid.New(),
			Email:        "user@example.com",
			PasswordHash: common.MustHashPassword("user"),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			IsAdmin:      false,
			Disabled:     false,
		},
	}

	for _, user := range users {
		err := r.Create(&user)
		if err != nil {
			if err.Error() == "user with email:("+user.Email+") already exists" {
				log.Println("User already exists: " + user.Email)
			} else {
				return errors.New("error seeding user repository: " + err.Error())
			}
		}
	}
	return nil
}

// initRepo is a helper function to initialize the database
func (r *userRepository) initRepo() error {
	query := `
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY,
			email TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			is_admin BOOLEAN NOT NULL,
			disabled BOOLEAN NOT NULL
		)
	`
	_, err := r.db.Exec(query)
	if err != nil {
		log.Println("Error running initRepo query for user repository: " + err.Error())
		return err
	}
	err = r.seedRepo()
	if err != nil {
		log.Println("Error seeding user repository: " + err.Error())
	}

	return nil
}

func NewUserRepository(db *sql.DB, env string) (users.UserRepository, error) {
	repo := &userRepository{db: db}
	if env == "dev" {
		log.Println("Initializing user repository")
		err := repo.initRepo()
		if err != nil {
			log.Println("Error initializing user repository: " + err.Error())
		}
	}
	return repo, nil
}
