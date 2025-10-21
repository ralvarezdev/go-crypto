package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

// EncryptGCM encrypts a string using the AES algorithm with the GCM block cipher mode
//
// Parameters:
//
//   - plainText: The plain text to encrypt
//   - key: The key to use for encryption (must be 16, 24 or 32 bytes long)
//
// Returns:
//
//   - A pointer to the encrypted string in hexadecimal format
//   - An error if any occurred during the encryption process
func EncryptGCM(plainText, key []byte) (*string, error) {
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
	if _, readErr := io.ReadFull(rand.Reader, nonce); readErr != nil {
		return nil, readErr
	}

	// Encrypt the plain text using the GCM block cipher
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// Return the encrypted cipher text as a hexadecimal string
	enc := hex.EncodeToString(cipherText)

	return &enc, nil
}

// DecryptGCM decrypts a string using the AES algorithm with the GCM block cipher mode
//
// Parameters:
//
// - encryptedText: A pointer to the encrypted string in hexadecimal format
// - key: The key to use for decryption (must be 16, 24 or 32 bytes long)
//
// Returns:
//
// - A pointer to the decrypted plain text string
// - An error if any occurred during the decryption process
func DecryptGCM(encryptedText *string, key []byte) (*string, error) {
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
