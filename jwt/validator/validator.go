package validator

import (
	"github.com/golang-jwt/jwt/v5"
	gocryptointerception "github.com/ralvarezdev/go-crypto/jwt/interception"
)

// Validator does parsing and validation of JWT tokens
type (
	Validator interface {
		GetToken(rawToken string) (*jwt.Token, error)
		GetClaims(rawToken string) (*jwt.MapClaims, error)
		GetValidatedClaims(
			rawToken string,
			interception gocryptointerception.Interception,
		) (*jwt.MapClaims, error)
	}
)
