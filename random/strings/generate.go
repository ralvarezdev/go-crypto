package strings

import (
	"encoding/hex"

	gocryptorandombytes "github.com/ralvarezdev/go-crypto/random/bytes"
)

// Generate generates a random string of the specified length
func Generate(length int) (string, error) {
	bytes, err := gocryptorandombytes.Generate(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateN generates N random strings of the specified length
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
