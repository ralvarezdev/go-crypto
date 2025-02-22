package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

// EncryptGCM encrypts a string using the AES algorithm with the GCM block cipher mode
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the plain text using the GCM block cipher
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// Return the encrypted cipher text as a hexadecimal string
	enc := hex.EncodeToString(cipherText)

	return &enc, nil
}

// DecryptGCM decrypts a string using the AES algorithm with the GCM block cipher mode
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

// EncryptCTR encrypts a string using the AES algorithm with the CTR block cipher mode
func EncryptCTR(plainText, key []byte) (*string, error) {
	// Create a new AES cipher block with the generated key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new CTR block cipher with the AES cipher block
	ctr := cipher.NewCTR(block, key)

	// Encrypt the plain text using the CTR block cipher
	cipherText := make([]byte, len(plainText))
	ctr.XORKeyStream(cipherText, plainText)

	// Return the encrypted cipher text as a hexadecimal string
	enc := hex.EncodeToString(cipherText)

	return &enc, nil
}

// DecryptCTR decrypts a string using the AES algorithm with the CTR block cipher mode
func DecryptCTR(encryptedText *string, key []byte) (*string, error) {
	// Check if the encrypted text is nil
	if encryptedText == nil {
		return nil, ErrNilEncryptedText
	}

	// Create a new AES cipher block with the generated key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new CTR block cipher with the AES cipher block
	ctr := cipher.NewCTR(block, key)

	// Decode the encrypted text from a hexadecimal string
	cipherText, err := hex.DecodeString(*encryptedText)
	if err != nil {
		return nil, err
	}

	// Decrypt the encrypted text using the CTR block cipher
	plainText := make([]byte, len(cipherText))
	ctr.XORKeyStream(plainText, cipherText)

	// Return the decrypted plain text
	dec := string(plainText)

	return &dec, nil
}
