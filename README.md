# Password Hash Using Golang

This showcases a simple way to create the following using Golang:

- Password Hashing
- Encryping and Decryping data

## Pasword Hashing
The function I will demonstrate will use `PBKDF2` with `SHA-256` as the underlying hashing algorithm.

We need to install the `golang.org/x/crypto/pbkdf2` package to use `PBKDF2`:
```
go get golang.org/x/crypto/pbkdf2
```


The `salt` value should be randomly generated and stored with the hashed password.
This is needed because lets say we are using the hash function to secure a users password, but then another user creates a new account with the same password. The `salt` would be used to differentiate between the two users.
So when we store a hashed password in this example, the `salt` would be stored along with the hashed password.

For my demonstration, we will first create a function that generates a random salt into bytes:
```
func generateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
```
- We convert the size int into a byte array.
- We then use `rand.Read` to generate a random number into the byte array.
- We then return the byte array and any errors that may have occurred.

Then we will use that salt to hash the password:
```
func hashPassword(password string, salt []byte) string {
	key := pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(key)
}
```
- `pbkdf2.Key` is the function that does the actual hashing.
- `10000` is the number of iterations. This can be increased to offer extra security. Some systems use 100,000+.
- `32` is the length of the key.
- `sha256.New` is the hashing algorithm.
- `base64.StdEncoding` is the encoding used to convert the binary key to a string. This is what will be stored in the database. Base64 is a common encoding used for binary data for security reasons and for easy storage.

We can verify the hash using the following function:
```
func verifyPassword(storedHash string, password string, salt []byte) bool {
	newHash := hashPassword(password, salt)
	return storedHash == newHash
}
```

## Encrypting & Decrypting Data
In my demonstration we will encrypt the data by first converting the data into a list of bytes then passing that into the encrypt function to return random bytes.
The decrypt function takes the encrypted data and returns the data into bytes which can then be easily converted into a string.

In order for both functions to work we need a **Master Key** which you could compare to as an API key in order for the two functions to work. This master key is a secret cryptographic key used to both encrypt and decrypt data. It must be kept secure because anyone with access to the master key can decrypt sensitive information. Similar to an API key, it acts as a crucial credential that enables secure operations. In this case, the master key is used by the AES algorithm to generate encrypted output and later retrieve the original plaintext.

For my approach I will use `openssl` to create my raw master key in bash then turn that into bytes for my example. In production the raw master key would be stored in an envrioment variable and not be viusible in the codebase.
```
// create raw master key in bash terminal
openssl rand -base64 32

// creating a global masterKey variable in bytes
var masterKey = []byte("+bgzo+wLkcDegCo3xMi7RYxu3qvm3CTVTB9Mpr5V0zg=")
```

Creating an encryption function using wteh master key:
```
// encrypt encrypts the given data using AES-GCM (Galois/Counter Mode)
func encrypt(data []byte) ([]byte, error) {
	// Create a new AES cipher block using the master key
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
	nonce := make([]byte, gcm.NonceSize()) // GCM nonce should be unique per encryption
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
```


Creating a decryption function using the master key
```
// decrypt decrypts the given encrypted data using AES-GCM
func decrypt(data []byte) ([]byte, error) {
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
```