package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

// Encrypt encrypts a string using the AES algorithm
func Encrypt(plainText, key []byte) (*string, error) {
	// Create a new AES cipher block with the generated key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM block cipher with the AES cipher block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a new nonce for the GCM block cipher
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the plain text using the GCM block cipher
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// Return the encrypted cipher text as a hexadecimal string
	enc := hex.EncodeToString(cipherText)

	return &enc, nil
}

// Decrypt decrypts a string using the AES algorithm
func Decrypt(encryptedText *string, key []byte) (*string, error) {
	// Check if the encrypted text is nil
	if encryptedText == nil {
		return nil, ErrNilEncryptedText
	}

	// Create a new AES cipher block with the generated key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM block cipher with the AES cipher block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decode the encrypted text from a hexadecimal string
	cipherText, err := hex.DecodeString(*encryptedText)
	if err != nil {
		return nil, err
	}

	// Get the nonce size from the GCM block cipher
	nonceSize := gcm.NonceSize()

	// Get the nonce from the encrypted text
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

	// Decrypt the encrypted text using the GCM block cipher
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	// Return the decrypted plain text
	dec := string(plainText)

	return &dec, nil
}
