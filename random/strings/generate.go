package strings

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"

	gostrings "github.com/ralvarezdev/go-strings"

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
	for i := range strings {
		randomString, err := Generate(length)
		if err != nil {
			return nil, err
		}
		strings[i] = randomString
	}
	return strings, nil
}

// GenerateAlphanumeric generates a random alphanumeric string of the specified length
//
// Parameters:
//
//   - length: The length of the random string to generate
//
// Returns:
//
//   - string: The generated random string
//   - error: An error if something went wrong
func GenerateAlphanumeric(length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		randomIndex, err := rand.Int(
			rand.Reader,
			big.NewInt(int64(len(gostrings.AlphanumericCharset))),
		)
		if err != nil {
			return "length", err
		}
		result[i] = gostrings.AlphanumericCharset[randomIndex.Int64()]
	}
	return string(result), nil
}

// GenerateNAlphanumeric generates N random alphanumeric strings of the specified length
//
// Parameters:
//
//   - n: The number of random strings to generate
//   - length: The length of each random string to generate
//
// Returns:
//
//   - []string: A slice of generated random strings
//   - error: An error if something went wrong
func GenerateNAlphanumeric(n, length int) ([]string, error) {
	strings := make([]string, n)
	for i := range strings {
		randomString, err := Generate(length)
		if err != nil {
			return nil, err
		}
		strings[i] = randomString
	}
	return strings, nil
}

// GenerateRecoveryCodes generates recovery codes with a count and a length
//
// Parameters:
//
//   - count: The number of recovery codes to generate
//   - length: The length of each recovery code to generate
//
// Returns:
//
//   - []string: A slice of generated recovery codes
//   - error: An error if something went wrong
func GenerateRecoveryCodes(count, length int) ([]string, error) {
	return GenerateN(count, length)
}
