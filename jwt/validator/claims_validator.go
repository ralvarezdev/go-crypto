package validator

import (
	"github.com/golang-jwt/jwt/v5"
	gocryptointerception "github.com/ralvarezdev/go-crypto/jwt/interception"
)

// ClaimsValidator interface
type ClaimsValidator interface {
	ValidateClaims(claims *jwt.MapClaims, interception gocryptointerception.Interception) (bool, error)
}
