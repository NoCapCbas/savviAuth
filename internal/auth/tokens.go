package domains

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

var (
	accessTokenKey  = []byte("ACCESS_TOKEN_SECRET_KEY")
	refreshTokenKey = []byte("REFRESH_TOKEN_SECRET_KEY")
)

type Claims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func GenerateTokenPair(userID string) (*TokenPair, error) {
	// Generate access token
	accessToken, err := generateToken(userID, accessTokenKey, 15*time.Minute)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := generateToken(userID, refreshTokenKey, 1*24*time.Hour)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func generateToken(userID string, key []byte, expiration time.Duration) (string, error) {
	expirationTime := time.Now().Add(expiration)
	claims := &Claims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Id:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func ValidateAccessToken(tokenString string) (*Claims, error) {
	return validateToken(tokenString, accessTokenKey)
}

func ValidateRefreshToken(tokenString string) (*Claims, error) {
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

func RefreshTokens(refreshToken string) (*TokenPair, error) {
	claims, err := ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return GenerateTokenPair(claims.UserID)
}
