package users

import (
	"time"

	"github.com/google/uuid"
)

// User data model
type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	IsAdmin      bool      `json:"is_admin"`
	Disabled     bool      `json:"disabled"`
}

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(user *User) error
	GetByID(id uuid.UUID) (*User, error)
	GetByUsername(username string) (*User, error)
	GetByEmail(email string) (*User, error)
	Update(user *User) error
	Delete(id uuid.UUID) error
	List() ([]*User, error)
}

// UserService defines the interface for user-related business logic
type UserService interface {
	Register(username, email, password string) (*User, error)
	Authenticate(username, password string) (*User, error)
	GetUser(id uuid.UUID) (*User, error)
	GetUserByEmail(email string) (*User, error)
	UpdateUser(user *User) error
	DisableUser(id uuid.UUID) error
	DeleteUser(id uuid.UUID) error
	ListUsers() ([]*User, error)
}

// UserHandler handles user-related HTTP requests
type UserHandler struct {
	UserService UserService
}
