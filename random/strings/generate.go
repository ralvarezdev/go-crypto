package strings

import (
	"encoding/hex"

	gocryptorandombytes "github.com/ralvarezdev/go-crypto/random/bytes"
)

// Generate generates a random string of the specified length
//
// Parameters:
//
//   - length: The length of the random string to generate.
//
// Returns:
//
//   - A random string of the specified length in hexadecimal format.
//   - An error if there was an issue generating the random bytes.
func Generate(length int) (string, error) {
	bytes, err := gocryptorandombytes.Generate(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateN generates N random strings of the specified length
//
// Parameters:
//
//   - n: The number of random strings to generate.
//   - length: The length of each random string.
//
// Returns:
//
//   - A slice containing N random strings of the specified length in hexadecimal format.
//   - An error if there was an issue generating any of the random strings.
func GenerateN(n, length int) ([]string, error) {
	strings := make([]string, n)
	for i := 0; i < n; i++ {
		randomString, err := Generate(length)
		if err != nil {
			return nil, err
		}
		strings[i] = randomString
	}
	return strings, nil
}
