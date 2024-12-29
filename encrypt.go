package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

const Secret string = "abc&1*~#^2^#s0^=)^^7%b34"

func Encoded(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// encryption function
func Encrypt(text, Secret string) (string, error) {
	block, err := aes.NewCipher([]byte(Secret))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return Encoded(cipherText), nil
}

func Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

// decryption function
func Decrypt(text, Secret string) (string, error) {
	block, err := aes.NewCipher([]byte(Secret))
	if err != nil {
		return "", err
	}
	cipherText := Decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

// print the encrypted or decrypted message
func main() {
	fmt.Println("Do you want to encode or decode a message? (e/d)")
	var choice string
	fmt.Scanln(&choice)

	if choice == "e" {
		fmt.Println("Type message to encode")
		fmt.Println("-----------------------")
		var StringtoEncrypt string
		fmt.Scanln(&StringtoEncrypt)
		encText, err := Encrypt(StringtoEncrypt, Secret)
		if err != nil {
			fmt.Println("error encrypting your classified text: ", err)
		} else {
			fmt.Println("Encoded text:", encText)
		}
	} else if choice == "d" {
		fmt.Println("Type message to decode")
		fmt.Println("-----------------------")
		var StringtoDecrypt string
		fmt.Scanln(&StringtoDecrypt)
		decText, err := Decrypt(StringtoDecrypt, Secret)
		if err != nil {
			fmt.Println("error decrypting your classified text: ", err)
		} else {
			fmt.Println("Decoded text:", decText)
		}
	} else {
		fmt.Println("Invalid choice. Please enter 'e' to encode or 'd' to decode.")
	}
}
