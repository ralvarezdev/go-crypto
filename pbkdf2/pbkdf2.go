package pbkdf2

import (
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// DeriveKey derives a key from the password using the PBKDF2 algorithm
//
// Parameters:
//
//   - password: the password to derive the key from
//   - salt: the salt to use for the key derivation
//   - iterations: the number of iterations to use for the key derivation
//   - keyLength: the length of the derived key in bytes
//   - hashFn: the hash function to use for the key derivation (e.g., sha256.New)
//
// Returns:
//
//   - the derived key as a byte slice
func DeriveKey(
	password string,
	salt []byte,
	iterations int,
	keyLength int,
	hashFn func() hash.Hash,
) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keyLength, hashFn)
}
