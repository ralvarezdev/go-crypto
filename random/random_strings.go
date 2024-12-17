package random

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateNRandomStrings generates n random strings of the specified length
func GenerateNRandomStrings(n, length int) ([]string, error) {
	strings := make([]string, n)
	for i := 0; i < n; i++ {
		randomString, err := GenerateRandomString(length)
		if err != nil {
			return nil, err
		}
		strings[i] = randomString
	}
	return strings, nil
}
