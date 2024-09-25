package users

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type userService struct {
	repo UserRepository
}

func NewUserService(repo UserRepository) UserService {
	return &userService{repo: repo}
}

func (s *userService) Register(username, email, password string) (*User, error) {
	// Check if user already exists
	existingUser, _ := s.repo.GetByEmail(email)
	if existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create new user
	newUser := &User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsAdmin:      false,
		Disabled:     false,
	}

	// Save user to repository
	err = s.repo.Create(newUser)
	if err != nil {
		return nil, err
	}

	return newUser, nil
}

func (s *userService) Authenticate(email, password string) (*User, error) {
	user, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

func (s *userService) GetUser(id uuid.UUID) (*User, error) {
	return s.repo.GetByID(id)
}

func (s *userService) GetUserByEmail(email string) (*User, error) {
	return s.repo.GetByEmail(email)
}

func (s *userService) UpdateUser(user *User) error {
	user.UpdatedAt = time.Now()
	return s.repo.Update(user)
}

func (s *userService) DisableUser(id uuid.UUID) error {
	user, err := s.repo.GetByID(id)
	if err != nil {
		return err
	}
	user.Disabled = true
	return s.repo.Update(user)
}

func (s *userService) DeleteUser(id uuid.UUID) error {
	return s.repo.Delete(id)
}

func (s *userService) ListUsers() ([]*User, error) {
	return s.repo.List()
}
