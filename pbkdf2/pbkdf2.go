package pbkdf2

import (
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// DeriveKey derives a key from the password using the PBKDF2 algorithm
func DeriveKey(
	password string,
	salt []byte,
	iterations int,
	keyLength int,
	hashFn func() hash.Hash,
) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keyLength, hashFn)
}
