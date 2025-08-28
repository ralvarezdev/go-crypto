package uuid

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// NewUUIDv4 generates an RFC 4122 version 4 UUID (random).
//
// Returns:
//
// A string representing the UUID and an error if any occurred during generation.
func NewUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}

	// Set version (4)
	b[6] = (b[6] & 0x0F) | 0x40
	// Set variant (RFC 4122)
	b[8] = (b[8] & 0x3F) | 0x80

	u := fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%04x%08x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		binary.BigEndian.Uint16(b[10:12]),
		binary.BigEndian.Uint32(b[12:16]),
	)
	return u, nil
}
