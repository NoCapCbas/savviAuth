package auth

import (
	"os"
)

var (
	accessTokenKey  = []byte(os.Getenv("ACCESS_TOKEN_SECRET_KEY"))
	refreshTokenKey = []byte(os.Getenv("REFRESH_TOKEN_SECRET_KEY"))
)

// TokenPair data model
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TokenService interface
type TokenService interface {
	// GenerateTokenPair generates a new access and refresh token pair
	GenerateTokenPair(userID string) (*TokenPair, error)
	// ValidateAccessToken validates an access token
	ValidateAccessToken(tokenString string) (string, error)
	// RefreshTokenPair refreshes a token pair, uses GenerateTokenPair Action internally
	RefreshTokenPair(refreshToken string) (*TokenPair, error)
}

// No Token Repository,
// token will be self sufficient
