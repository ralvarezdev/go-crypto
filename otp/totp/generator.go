package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

// Inspired by:
// https://medium.com/@firateski/coding-totp-generator-with-go-a31668ef955e
// https://medium.com/@nathanbcrocker/building-a-time-based-one-time-password-totp-generator-in-go-a-deep-dive-into-2fa-implementation-043c1000e09f

// GenerateKey generates a random key with a length of N bytes
func GenerateKey(length int) (string, error) {
	// Create a byte slice with the length of N bytes
	key := make([]byte, length)

	// Read N random bytes into the byte slice
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	// Encode the byte slice to a base32 string
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key), nil
}

// ComputeHMAC computes the HMAC with a key, a message value and a hash function
func ComputeHMAC(key string, msg uint64, hashFn func() hash.Hash) ([]byte, error) {
	// Decode the base32 value with no padding
	key = strings.ToUpper(key)
	keyByte, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(key)
	if err != nil {
		return nil, err
	}

	// Create a byte with the message value
	msgByte := make([]byte, 8)

	binary.BigEndian.PutUint64(msgByte, msg)

	// Create a new HMAC hash with the key
	hmacHash := hmac.New(hashFn, keyByte)
	hmacHash.Write(msgByte)

	// Return the created HMAC hash as a byte
	return hmacHash.Sum(nil), nil
}

// ComputeTimedHMAC computes the HMAC hash with a key, a time value, a time step and a hash function
func ComputeTimedHMAC(key string, time time.Time, timeStep uint64, hashFn func() hash.Hash) ([]byte, error) {
	// Compute the message value
	msg := uint64(time.Unix()) / timeStep

	// Compute the HMAC hash
	return ComputeHMAC(key, msg, hashFn)
}

// ComputeTimedHMACSha1 computes the HMAC hash with a key, a time value and a time step using SHA1
func ComputeTimedHMACSha1(key string, time time.Time, timeStep uint64) ([]byte, error) {
	return ComputeTimedHMAC(key, time, timeStep, sha1.New)
}

// Truncate truncates the hash to a digit count and returns the OTP. The digit count must be between 6 and 8
func Truncate(hash []byte, digitCount int) (string, error) {
	if digitCount < DigitCountStart || digitCount > DigitCountEnd {
		return "", fmt.Errorf("digit count must be between %v and %v", DigitCountStart, DigitCountEnd)
	}

	// Calculate the offset from the last byte of the hash. The offset is the last 4 bits of the last byte
	offset := uintptr(hash[len(hash)-1] & 0xf)

	// Extract 4 bytes from the hash starting from the calculated offset
	extractedValue := int(hash[offset])<<24 | int(hash[offset+1])<<16 | int(hash[offset+2])<<8 | int(hash[offset+3])

	// Ensure the extracted value is positive by BITWISE AND operation
	extractedPositiveValue := int64(extractedValue & 0x7fffffff)

	// Calculate the OTP by taking the modulus of the extracted positive value with 10^digitCount
	otp := int(extractedPositiveValue % int64(math.Pow10(digitCount)))

	// Format the OTP with leading zeros to fit the digit count
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digitCount), otp), nil
}
