package validator

import (
	"errors"
)

var (
	InvalidTokenError            = errors.New("invalid token")
	UnexpectedSigningMethodError = errors.New("unexpected signing method")
	InvalidClaimsError           = errors.New("invalid claims")
	NilClaimsValidatorError      = errors.New("claims validator cannot be nil")
)
