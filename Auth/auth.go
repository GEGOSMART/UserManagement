package Auth

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var signingKey = []byte("geosmartsigningkey")

func GenerateJWT(user bool, username string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["user"] = username
	var timeToken time.Duration
	if user {
		timeToken = time.Hour * 730
	} else {
		timeToken = time.Hour * 24
	}
	claims["exp"] = time.Now().Add(timeToken).Unix()

	tokenString, err := token.SignedString(signingKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}
