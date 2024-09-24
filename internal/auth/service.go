package domains

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type authService struct {
	repo AuthRepository
}

// AccessClaims struct
type AccessClaims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

// RefreshClaims struct
type RefreshClaims struct {
	AccessToken string `json:"access_token"`
	jwt.StandardClaims
}

func (s *authService) GenerateTokenPair(userID string) (*TokenPair, error) {
	// Generate access token, uses userID as identifier
	// this allows for easy access to user requested resources
	accessToken, err := generateToken(userID, accessTokenKey, 30*time.Minute)
	if err != nil {
		return nil, err
	}

	// Generate refresh token, uses access token as identifier
	// this allows for easy token refresh, by validating the access token
	// and then generating a new pair
	refreshToken, err := generateToken(accessToken, refreshTokenKey, 1*24*time.Hour)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func generateToken(identifier string, key []byte, expiration time.Duration) (string, error) {
	expirationTime := time.Now().Add(expiration)
	claims := &AccessClaims{
		Identifier: identifier,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Id:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func (s *authService) ValidateAccessToken(tokenString string) (*Claims, error) {
	return validateToken(tokenString, accessTokenKey)
}

func validateRefreshToken(tokenString string) (*Claims, error) {
	return validateToken(tokenString, refreshTokenKey)
}

func validateToken(tokenString string, key []byte) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func (s *authService) RefreshTokenPair(refreshToken string) (*TokenPair, error) {
	claims, err := validateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return GenerateTokenPair(claims.UserID)
}
