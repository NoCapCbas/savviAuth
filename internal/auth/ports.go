package auth

import (
	"os"
	"time"
)

var (
	accessTokenKey  = []byte(os.Getenv("ACCESS_TOKEN_SECRET_KEY"))
	refreshTokenKey = []byte(os.Getenv("REFRESH_TOKEN_SECRET_KEY"))
)

// TokenPair data model
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// TokenService interface
type TokenService interface {
	GenerateTokenPair(userID string) (*TokenPair, error)
	ValidateAccessToken(tokenString string) (string, error)
	ValidateRefreshToken(tokenString string) (string, error)
}

// No Token Repository,
// token will be self sufficient
