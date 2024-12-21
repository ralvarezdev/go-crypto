package random

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateRandomBytes generates a random byte slice of the specified length
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
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
