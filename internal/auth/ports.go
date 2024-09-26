package auth

// TokenPair data model
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// AuthService interface
type AuthService interface {
	// GenerateTokenPair generates a new access and refresh token pair
	GenerateTokenPair(userID string) (*TokenPair, error)
	// ValidateAccessToken validates an access token
	ValidateAccessToken(tokenString string) (*AccessClaims, error)
	// ValidateRefreshToken validates a refresh token
	ValidateRefreshToken(tokenString string) (*RefreshClaims, error)
}

// No Token Repository,
// token will be self sufficient
type AuthHandler struct {
	AuthService AuthService
}
