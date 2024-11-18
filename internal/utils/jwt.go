package utils

import (
	"fmt"
	"time"
	"github.com/dgrijalva/jwt-go"
)

var jwtSecret = []byte("your-secret-key") // In production, load this from environment variables

type Claims struct {
	UserID  string `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
	jwt.StandardClaims
}

func GenerateToken(userID string, isAdmin bool) (string, error) {
	// Create the Claims
	claims := &Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyToken(tokenString string) (string, bool, error) {
	// Parse token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return "", false, err
	}

	if !token.Valid {
		return "", false, fmt.Errorf("invalid token")
	}

	return claims.UserID, claims.IsAdmin, nil
}