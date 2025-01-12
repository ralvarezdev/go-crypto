package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	gocryptorandomutf8 "github.com/ralvarezdev/go-crypto/random/strings/utf8"
	"hash"
	"math"
	"net/url"
	"strings"
	"time"
)

// Inspired by:
// https://medium.com/@firateski/coding-totp-generator-with-go-a31668ef955e
// https://medium.com/@nathanbcrocker/building-a-time-based-one-time-password-totp-generator-in-go-a-deep-dive-into-2fa-implementation-043c1000e09f

// Url struct for the TOTP URL
type Url struct {
	BaseURL   string
	Issuer    string
	Algorithm string
	Digits    int
	Period    int
}

// NewUrl creates a new URL
func NewUrl(issuer, algorithm string, digits, period int) *Url {
	return &Url{
		BaseURL:   BaseURL,
		Issuer:    issuer,
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
	}
}

// Generate generates a formatted URL with the hash and secret
func (u *Url) Generate(secret, accountName string) (string, error) {
	// Create the URL with query parameters
	U, err := url.Parse(u.BaseURL)
	if err != nil {
		return "", err
	}

	// Set the path and query parameters
	U.Path += fmt.Sprintf("/%s:%s", u.Issuer, accountName)
	q := U.Query()
	q.Set("secret", secret)
	q.Set("issuer", u.Issuer)
	q.Set("algorithm", strings.ToUpper(u.Algorithm))
	q.Set("digits", fmt.Sprintf("%d", u.Digits))
	q.Set("period", fmt.Sprintf("%d", u.Period))
	U.RawQuery = q.Encode()

	return U.String(), nil
}

// NewSecret generates a random secret with a length of N bytes
func NewSecret(length int) (string, error) {
	// Create a byte slice with the length of N bytes
	secret := make([]byte, length)

	// Read N random bytes into the byte slice
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	// Encode the byte slice to a base32 string
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// ComputeHMAC computes the HMAC with a secret, a message value and a hash function
func ComputeHMAC(secret string, msg uint64, hashFn func() hash.Hash) (
	[]byte,
	error,
) {
	// Decode the base32 value with no padding
	secret = strings.ToUpper(secret)
	secretByte, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return nil, err
	}

	// Create a byte with the message value
	msgByte := make([]byte, 8)

	binary.BigEndian.PutUint64(msgByte, msg)

	// Create a new HMAC hash with the secret
	hmacHash := hmac.New(hashFn, secretByte)
	hmacHash.Write(msgByte)

	// Return the created HMAC hash as a byte
	return hmacHash.Sum(nil), nil
}

// ComputeTimedHMAC computes the HMAC hash with a secret, a time value, a time step and a hash function
func ComputeTimedHMAC(
	secret string,
	time time.Time,
	period uint64,
	hashFn func() hash.Hash,
) ([]byte, error) {
	// Compute the message value
	msg := uint64(time.Unix()) / period

	// Compute the HMAC hash
	return ComputeHMAC(secret, msg, hashFn)
}

// ComputeTimedHMACSha1 computes the HMAC hash with a secret, a time value and a time step using SHA1
func ComputeTimedHMACSha1(secret string, time time.Time, period uint64) (
	[]byte,
	error,
) {
	return ComputeTimedHMAC(secret, time, period, sha1.New)
}

// Truncate truncates the hash to a digit count and returns the OTP. The digit count must be between 6 and 8
func Truncate(hash []byte, digits int) (string, error) {
	if digits < DigitCountStart || digits > DigitCountEnd {
		return "", fmt.Errorf(
			"digit count must be between %v and %v",
			DigitCountStart,
			DigitCountEnd,
		)
	}

	// Calculate the offset from the last byte of the hash. The offset is the last 4 bits of the last byte
	offset := uintptr(hash[len(hash)-1] & 0xf)

	// Extract 4 bytes from the hash starting from the calculated offset
	extractedValue := int(hash[offset])<<24 | int(hash[offset+1])<<16 | int(hash[offset+2])<<8 | int(hash[offset+3])

	// Ensure the extracted value is positive by BITWISE AND operation
	extractedPositiveValue := int64(extractedValue & 0x7fffffff)

	// Calculate the OTP by taking the modulus of the extracted positive value with 10^digits
	otp := int(extractedPositiveValue % int64(math.Pow10(digits)))

	// Format the OTP with leading zeros to fit the digit count
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), otp), nil
}

// GenerateTOTPSha1 generates a TOTP with a secret, a time value, a time step and a digit count using SHA1
func GenerateTOTPSha1(
	secret string,
	time time.Time,
	period uint64,
	digits int,
) (string, error) {
	// Compute the HMAC hash with SHA1
	hmacHash, err := ComputeTimedHMACSha1(secret, time, period)
	if err != nil {
		return "", err
	}

	// Truncate the hash to the digit count
	return Truncate(hmacHash, digits)
}

// CompareTOTPSha1 compares a TOTP code with a secret, a time value, a time step and a digit count using SHA1
func CompareTOTPSha1(
	code, secret string,
	time time.Time,
	period uint64,
	digits int,
) (bool, error) {
	// Generate the TOTP with the secret, time, period and digits
	generatedCode, err := GenerateTOTPSha1(secret, time, period, digits)
	if err != nil {
		return false, err
	}
	return generatedCode == code, nil
}

// GenerateRecoveryCodes generates recovery codes with a count and a length
func GenerateRecoveryCodes(count, length int) (*[]string, error) {
	return gocryptorandomutf8.GenerateN(count, length)
}
