package totp

import (
	"fmt"
	"net/url"
	"strings"
)

type (
	// URL struct for the TOTP URL
	URL struct {
		baseURL   string
		issuer    string
		algorithm string
		digits    int
		period    int
	}
)

// NewURL creates a new URL
//
// Parameters:
//
// - issuer: the issuer of the TOTP
// - algorithm: the algorithm used to generate the TOTP
// - digits: the number of digits of the TOTP
// - period: the period of the TOTP
//
// Returns:
//
// - *URL: the created URL
func NewURL(issuer, algorithm string, digits, period int) *URL {
	return &URL{
		baseURL:   BaseURL,
		issuer:    issuer,
		algorithm: algorithm,
		digits:    digits,
		period:    period,
	}
}

// Generate generates a formatted URL with the hash and secret
//
// Parameters:
//
// - secret: the secret used to generate the URL
// - accountName: the account name used to generate the URL
//
// Returns:
//
// - string: the generated URL
// - error: if any error occurs during the process
func (u URL) Generate(secret, accountName string) (string, error) {
	// Create the URL with query parameters
	U, err := url.Parse(u.baseURL)
	if err != nil {
		return "", err
	}

	// Set the path and query parameters
	U.Path += fmt.Sprintf("/%s:%s", u.issuer, accountName)
	q := U.Query()
	q.Set("secret", secret)
	q.Set("issuer", u.issuer)
	q.Set("algorithm", strings.ToUpper(u.algorithm))
	q.Set("digits", fmt.Sprintf("%d", u.digits))
	q.Set("period", fmt.Sprintf("%d", u.period))
	U.RawQuery = q.Encode()

	return U.String(), nil
}
