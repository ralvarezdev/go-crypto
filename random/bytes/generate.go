package bytes

import (
	"crypto/rand"
	"io"
)

// Generate generates a random byte slice of the specified length
func Generate(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}
