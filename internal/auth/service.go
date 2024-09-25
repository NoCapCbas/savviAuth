package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type authService struct {
	accessTokenKey  []byte
	refreshTokenKey []byte
}

// AccessClaims struct, user_id used as identifier
type AccessClaims struct {
	Identifier string `json:"user_id"`
	jwt.StandardClaims
}

// RefreshClaims struct, access_token used as identifier
type RefreshClaims struct {
	Identifier string `json:"access_token"`
	jwt.StandardClaims
}

func (s *authService) GenerateTokenPair(userID string) (*TokenPair, error) {
	// Generate access token, uses userID as identifier
	// this allows for easy access to user requested resources
	accessToken, err := generateToken(userID, accessTokenKey, 30*time.Minute, "access")
	if err != nil {
		return nil, err
	}

	// Generate refresh token, uses access token as identifier
	// this allows for easy token refresh, by validating the access token
	// and then generating a new pair
	refreshToken, err := generateToken(accessToken, refreshTokenKey, 1*24*time.Hour, "refresh")
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func generateToken(identifier string, key []byte, expiration time.Duration, claimType string) (string, error) {
	expirationTime := time.Now().Add(expiration)
	var claims interface{}
	if claimType == "access" {
		claims = &AccessClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
				IssuedAt:  time.Now().Unix(),
				Id:        uuid.New().String(),
			},
		}
	} else if claimType == "refresh" {
		claims = &RefreshClaims{
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

func (s *authService) ValidateAccessToken(tokenString string) (*AccessClaims, error) {
	claims, err := validateToken(tokenString, s.accessTokenKey, "access")
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims.(*AccessClaims), nil
}

func (s *authService) ValidateRefreshToken(tokenString string) (*RefreshClaims, error) {
	claims, err := validateToken(tokenString, s.refreshTokenKey, "refresh")
	if err != nil {
		return nil, err
	}
	return claims.(*RefreshClaims), nil
}

func validateToken(tokenString string, key []byte, tokenType string) (jwt.Claims, error) {
	var claims jwt.Claims
	if tokenType == "access" {
		claims = &AccessClaims{}
	} else if tokenType == "refresh" {
		claims = &RefreshClaims{}
	}
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
