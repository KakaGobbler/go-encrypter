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

func main() {
	fmt.Println("Type message to encode")
	fmt.Println("-----------------------")
	var StringtoEncrypt string
	fmt.Scanln(&StringtoEncrypt)
	encrypit := StringtoEncrypt

	encText, err := Encrypt(encrypit, Secret)
	if err != nil {
		fmt.Println("error encrypting your classified text: ", err)
	}
	fmt.Println(encText)
}
