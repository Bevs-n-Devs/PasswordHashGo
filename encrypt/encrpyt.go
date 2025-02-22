package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func Encrypt(data []byte) ([]byte, error) {
	// create a new AES cipher block using the master key
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err // Return error if key is invalid
	}

	// Create a GCM (Galois Counter Mode) cipher from the AES block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err // Return error if GCM initialization fails
	}

	// Generate a nonce (unique number used only once) of required size
	nonce := make([]byte, gcm.NonceSize())   // GCM nonce should be unique per encryption
	_, err = io.ReadFull(rand.Reader, nonce) // Fill nonce with random bytes
	if err != nil {
		return nil, err // Return error if random generation fails
	}

	// Encrypt the data using AES-GCM
	// Seal appends encrypted data to nonce (authentication tag included)
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Return the concatenated nonce + ciphertext
	return append(nonce, ciphertext...), nil
}
