package main

import (
	"fmt"

	"github.com/Bevs-n-Devs/PasswordHashGo/hashpassword"
)

func main() {
	fmt.Println("Hashing Passwords")

	password := "password123" // user password

	// generate salt byte list of 32 bytes
	salt, err := hashpassword.GenerateSalt(32)
	if err != nil {
		fmt.Println("Error generating salt:", err.Error())
	}

	// hash the password with the salt
	hashedPassword := hashpassword.HashPassword(password, salt)
	fmt.Println("Original password:", password)
	fmt.Printf("Hashed password: %s\n", hashedPassword)

}
