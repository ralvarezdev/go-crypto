package main

import "errors"

var (
	FailedToHashPasswordError = errors.New("failed to hash password")
	PasswordNotHashedError    = errors.New("password is not hashed")
)
