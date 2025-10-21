package gocrypto

import "errors"

var (
	ErrFailedToHashPassword = errors.New("failed to hash password")
	ErrPasswordNotHashed    = errors.New("password is not hashed")
)
