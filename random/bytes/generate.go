package bytes

import (
	"crypto/rand"
	"io"
)

// Generate generates a random byte slice of the specified length
//
// Parameters:
//
//	length: The length of the byte slice to generate
//
// Returns:
//
//	A byte slice of the specified length containing random bytes, or an error if the generation fails
func Generate(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}
