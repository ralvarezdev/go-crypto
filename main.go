package main

import (
	gocryptototp "github.com/ralvarezdev/go-crypto/otp/totp"
)

func main() {
	// Test the package
	gocryptototp.TestTOTPGenerator("H2APBOUGPHU7QHJW4X6GOWCEK6MIJ7RO5SAR35DLLYBWVGESIA5Q")
}
