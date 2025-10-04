package totp

import (
	"fmt"
	"time"
)

// TestTOTPGenerator function
func TestTOTPGenerator(secret string) {
	// Constants
	const (
		digits = 6
		period = 30
	)

	// Create a new TOTP URL
	totpUrl := NewUrl("ralvarezdev", "sha1", digits, period)

	// Generate a new TOTP URL based on the secret
	formattedURL, _ := totpUrl.Generate(secret, "test")
	fmt.Printf("Secret TOTP URL: %s\n", formattedURL)

	// Generate a new TOTP code based on the secret
	totpCode, _ := GenerateTOTPSha1(secret, time.Now(), period, digits)
	fmt.Printf("Secret '%s' TOTP code: %s\n", secret, totpCode)

	// Generate a new TOTP secret
	newSecret, _ := NewSecret(32)
	fmt.Printf("New TOTP secret: %s\n", newSecret)

	// Generate a new TOTP URL with the secret
	formattedURL, _ = totpUrl.Generate(newSecret, "test")
	fmt.Printf("New TOTP URL: %s\n", formattedURL)

	// Generate a new TOTP code
	currentTime := time.Now()
	totpCode, _ = GenerateTOTPSha1(newSecret, currentTime, period, digits)
	fmt.Printf(
		"New TOTP code at %s: %s\n",
		currentTime.Format(time.RFC3339),
		totpCode,
	)
}
