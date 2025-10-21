package totp

import (
	"fmt"
	"time"
)

// TestTOTPGenerator function to test the TOTP generator
//
// Parameters:
//
//   - secret: the secret key to generate the TOTP code
func TestTOTPGenerator(secret string) {
	// Constants
	const (
		digits = 6
		period = 30
	)

	// Create a new TOTP URL
	totpURL := NewURL("ralvarezdev", "sha1", digits, period)

	// Generate a new TOTP URL based on the secret
	formattedURL, err := totpURL.Generate(secret, "test")
	if err != nil {
		fmt.Printf("Error generating TOTP URL: %v\n", err)
		return
	}
	fmt.Printf("Secret TOTP URL: %s\n", formattedURL)

	// Generate a new TOTP code based on the secret
	totpCode, err := GenerateTOTPSha1(secret, time.Now(), period, digits)
	if err != nil {
		fmt.Printf("Error generating TOTP code: %v\n", err)
		return
	}
	fmt.Printf("Secret '%s' TOTP code: %s\n", secret, totpCode)

	// Generate a new TOTP secret
	newSecret, err := NewSecret(32)
	if err != nil {
		fmt.Printf("Error generating new TOTP secret: %v\n", err)
		return
	}
	fmt.Printf("New TOTP secret: %s\n", newSecret)

	// Generate a new TOTP URL with the secret
	formattedURL, err = totpURL.Generate(newSecret, "test")
	if err != nil {
		fmt.Printf("Error generating new TOTP URL: %v\n", err)
		return
	}
	fmt.Printf("New TOTP URL: %s\n", formattedURL)

	// Generate a new TOTP code
	currentTime := time.Now()
	totpCode, err = GenerateTOTPSha1(newSecret, currentTime, period, digits)
	if err != nil {
		fmt.Printf("Error generating new TOTP code: %v\n", err)
		return
	}
	fmt.Printf(
		"New TOTP code at %s: %s\n",
		currentTime.Format(time.RFC3339),
		totpCode,
	)
}
