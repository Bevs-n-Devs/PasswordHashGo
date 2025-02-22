package main

import (
	"encoding/base64"
	"fmt"

	"github.com/Bevs-n-Devs/PasswordHashGo/encrypt"
	"github.com/Bevs-n-Devs/PasswordHashGo/hashpassword"
)

func main() {
	fmt.Println("Hashing Passwords")

	password := "password123" // user password

	// generate salt byte list of 32 bytes
	salt, err := hashpassword.GenerateSalt(32)
	if err != nil {
		fmt.Println("Error generating salt:", err.Error())
		return
	}

	// hash the password with the salt
	hashedPassword := hashpassword.HashPassword(password, salt)
	fmt.Println("Original password:", password)
	fmt.Printf("Hashed password: %s\n", hashedPassword)
	encryptDecrypt := `
Encrypting and Decrypting Data`
	fmt.Println(encryptDecrypt)
	encryptData := `
	Encrpyting Data
	`
	fmt.Println(encryptData)

	// encrypt the user data
	unencryptedData := []byte("hello world, hello Yaw!")
	encryptedData, err := encrypt.Encrypt(unencryptedData)
	if err != nil {
		fmt.Println("Error encrypting data:", err.Error())
		return
	}

	fmt.Printf("Unencrypted data: %s\n", unencryptedData)
	encodedEncryptedData := base64.StdEncoding.EncodeToString(encryptedData)
	fmt.Println("Encrypted data:", encodedEncryptedData)

	// decrypt the user data
	decryptData := `
	Decrypting Data
	`
	fmt.Println(decryptData)
	decryptedData, err := encrypt.Decrypt(encryptedData)
	if err != nil {
		fmt.Println("Error decrypting data:", err.Error())
		return
	}
	fmt.Printf("Decrypted data: %s\n", decryptedData)
}
