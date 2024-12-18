package validator

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	gocryptojwt "github.com/ralvarezdev/go-crypto/jwt"
	gocryptointerception "github.com/ralvarezdev/go-crypto/jwt/interception"
	goflagmode "github.com/ralvarezdev/go-flags/mode"
	"golang.org/x/crypto/ed25519"
)

// Ed25519Validator handles parsing and validation of JWT tokens with ED25519 public key
type Ed25519Validator struct {
	ed25519Key      *ed25519.PublicKey
	claimsValidator ClaimsValidator
	mode            *goflagmode.Flag
}

// NewEd25519Validator returns a new validator by parsing the given file path as an ED25519 public key
func NewEd25519Validator(
	publicKey []byte, claimsValidator ClaimsValidator, mode *goflagmode.Flag,
) (*Ed25519Validator, error) {
	// Check if either the token validator or the mode flag is nil
	if claimsValidator == nil {
		return nil, NilClaimsValidatorError
	}
	if mode == nil {
		return nil, goflagmode.NilModeFlagError
	}

	// Parse the public key
	key, err := jwt.ParseEdPublicKeyFromPEM(publicKey)
	if err != nil {
		return nil, gocryptojwt.UnableToParsePublicKeyError
	}

	// Ensure the key is of type ED25519 public key
	ed25519Key, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, gocryptojwt.InvalidKeyTypeError
	}

	return &Ed25519Validator{
		ed25519Key:      &ed25519Key,
		claimsValidator: claimsValidator,
		mode:            mode,
	}, nil
}

// GetToken parses the given JWT raw token
func (d *Ed25519Validator) GetToken(rawToken string) (*jwt.Token, error) {
	// Parse JWT and verify signature
	token, err := jwt.Parse(
		rawToken,
		func(rawToken *jwt.Token) (interface{}, error) {
			// Check to see if the token uses the expected signing method
			if _, ok := rawToken.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, UnexpectedSigningMethodError
			}
			return *d.ed25519Key, nil
		},
	)
	if err != nil {
		if !d.mode.IsProd() {
			return nil, err
		}

		switch {
		case errors.Is(err, UnexpectedSigningMethodError):
		case errors.Is(err, jwt.ErrSignatureInvalid):
		case errors.Is(err, jwt.ErrTokenExpired):
		case errors.Is(err, jwt.ErrTokenNotValidYet):
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, err
		default:
			return nil, InvalidTokenError
		}
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, InvalidTokenError
	}
	return token, nil
}

// GetClaims parses and validates the given JWT raw token
func (d *Ed25519Validator) GetClaims(rawToken string) (
	*jwt.MapClaims, error,
) {
	// Get the token
	token, err := d.GetToken(rawToken)
	if err != nil {
		return nil, err
	}

	// Get token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, InvalidClaimsError
	}

	return &claims, nil
}

// ValidateClaims validates the given claims
func (d *Ed25519Validator) ValidateClaims(
	rawToken string,
	interception gocryptointerception.Interception,
) (*jwt.MapClaims, error) {
	// Get the claims
	claims, err := d.GetClaims(rawToken)
	if err != nil {
		return nil, err
	}

	// Check if the token claims are valid
	areValid, err := d.claimsValidator.ValidateClaims(claims, interception)
	if err != nil {
		return nil, err
	}
	if !areValid {
		return nil, InvalidTokenError
	}

	return claims, nil
}

// GetValidatedClaims parses, validates and returns the claims of the given JWT raw token
func (d *Ed25519Validator) GetValidatedClaims(
	rawToken string,
	interception gocryptointerception.Interception,
) (
	*jwt.MapClaims, error,
) {
	// Validate the claims
	return d.ValidateClaims(rawToken, interception)
}
