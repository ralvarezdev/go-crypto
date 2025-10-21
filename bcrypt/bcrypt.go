package bcrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/bcrypt"

	gocrypto "github.com/ralvarezdev/go-crypto"
)

// HashPassword hashes a password using bcrypt
//
// Parameters:
//
//   - password: the password to hash
//   - cost: the cost parameter for the bcrypt hash
//
// Returns:
//
//   - the hashed password
//   - an error if the hashing fails
func HashPassword(password string, cost int) (string, error) {
	// Hash the password with SHA-256 if it is longer than 72 bytes
	passwordBytes := []byte(password)
	if len(passwordBytes) > 72 {
		passwordHash := sha256.Sum256(passwordBytes)
		passwordBytes = []byte(hex.EncodeToString(passwordHash[:]))
	}

	// Generate the hash
	hash, err := bcrypt.GenerateFromPassword(
		passwordBytes, cost,
	)
	if err != nil {
		return "", gocrypto.ErrFailedToHashPassword
	}

	return string(hash), nil
}

// CompareHashAndPassword compares a password with a hash
//
// Parameters:
//
//   - hash: the bcrypt hash
//   - password: the password to compare
//
// Returns:
//
//   - true if the password matches the hash, false otherwise
func CompareHashAndPassword(hash, password string) bool {
	// Hash the password with SHA-256 if it is longer than 72 bytes
	passwordBytes := []byte(password)
	if len(passwordBytes) > 72 {
		passwordHash := sha256.Sum256(passwordBytes)
		passwordBytes = []byte(hex.EncodeToString(passwordHash[:]))
	}

	// Compare the password with the hash
	err := bcrypt.CompareHashAndPassword([]byte(hash), passwordBytes)
	return err == nil
}

// IsHashed checks if a string is a bcrypt hash
//
// Parameters:
//
//   - str: the string to check
//
// Returns:
//
//   - true if the string is a bcrypt hash, false otherwise
func IsHashed(str string) bool {
	// bcrypt hashes are always 60 characters long
	if len(str) != 60 {
		return false
	}

	// Try to decode the hash
	err := bcrypt.CompareHashAndPassword([]byte(str), []byte{})
	if err != nil {
		return errors.Is(err, bcrypt.ErrMismatchedHashAndPassword)
	}
	return true
}
