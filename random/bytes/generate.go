package bytes

import (
	"crypto/rand"
)

// Generate generates a random byte slice of the specified length
func Generate(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
