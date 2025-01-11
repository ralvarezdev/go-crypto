package bcrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	gocrypto "github.com/ralvarezdev/go-crypto"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string, cost int) (string, error) {
	// Hash the password with SHA-256 if it is longer than 72 bytes
	passwordBytes := []byte(password)
	if len(passwordBytes) > 72 {
		passwordHash := sha256.Sum256(passwordBytes)
		password = hex.EncodeToString(passwordHash[:])
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
func CompareHashAndPassword(hash string, password string) bool {
	// Hash the password with SHA-256 if it is longer than 72 bytes
	passwordBytes := []byte(password)
	if len(passwordBytes) > 72 {
		passwordHash := sha256.Sum256(passwordBytes)
		password = hex.EncodeToString(passwordHash[:])
	}

	// Compare the password with the hash
	err := bcrypt.CompareHashAndPassword([]byte(hash), passwordBytes)
	if err != nil {
		return false
	}
	return true
}

// IsHashed checks if a string is a bcrypt hash
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
