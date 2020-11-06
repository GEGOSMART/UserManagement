package Auth

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var signingKey = []byte("geosmartsigningkey")

func GenerateJWT(user bool, id string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["user"] = id
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

func VerifyToken(tokenString string) (*jwt.Token, error) {
	token, error := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Something went wrong")
		}

		return signingKey, nil
	})

	if error != nil {
		return nil, error
	}

	if token.Valid {
		return token, nil
	} else {
		return nil, fmt.Errorf("Token invalid")
	}
}
