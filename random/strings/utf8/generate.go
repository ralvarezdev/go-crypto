package utf8

import (
	"crypto/rand"
	"math/big"
)

var (
	// Charset is the character set used to generate random UTF-8 safe strings
	Charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// Generate generates a random UTF-8 safe string of the specified length
func Generate(length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		randomIndex, err := rand.Int(
			rand.Reader,
			big.NewInt(int64(len(Charset))),
		)
		if err != nil {
			return "", err
		}
		result[i] = Charset[randomIndex.Int64()]
	}
	return string(result), nil
}

// GenerateN generates N random strings of the specified length
func GenerateN(n, length int) (*[]string, error) {
	strings := make([]string, n)
	for i := 0; i < n; i++ {
		randomString, err := Generate(length)
		if err != nil {
			return nil, err
		}
		strings[i] = randomString
	}
	return &strings, nil
}

// GenerateRecoveryCodes generates recovery codes with a count and a length
func GenerateRecoveryCodes(count, length int) (*[]string, error) {
	return GenerateN(count, length)
}
