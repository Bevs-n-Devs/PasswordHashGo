package hashpassword

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
)

/*
GenerateSalt generates a random salt of the specified size the user can use to hash their password.

The salt is used to protect against rainbow table attacks.

The salt is returned as a byte slice.
*/
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

/*
HashPassword hashes the password using the PBKDF2 algorithm with a 10000 iteration count and a 32 byte key length.

Returns the hashed password as a base64 encoded string.
*/
func HashPassword(password string, salt []byte) string {
	key := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(key)
}

/*
VerifyPassword verifies the password against the stored hash.

It does this by hashing the password with the salt and comparing it to the stored hash.

Returns true if the password is correct, false otherwise.
*/
func VerifyPassword(storedHash string, password string, salt []byte) bool {
	newHash := HashPassword(password, salt)
	return newHash == storedHash
}
