package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
)

func Decrypt(data []byte) ([]byte, error) {
	// Create a new AES cipher block using the same master key
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err // Return error if key is invalid
	}

	// Create a GCM cipher from the AES block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err // Return error if GCM initialization fails
	}

	// Extract the nonce from the start of the encrypted data
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the ciphertext using AES-GCM
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err // Return error if decryption fails
	}

	// Return the decrypted plaintext
	return plaintext, nil
}
