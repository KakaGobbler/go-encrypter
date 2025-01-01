package main

import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "os"
    "strings"
)

var bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

// Encoded encodes bytes to a base64 string
func Encoded(b []byte) string {
    return base64.StdEncoding.EncodeToString(b)
}

// padKey pads or truncates the key to 32 bytes
func padKey(key string) []byte {
    paddedKey := make([]byte, 32)
    copy(paddedKey, key)
    return paddedKey
}

// Encrypt encrypts the given text using the provided secret key
func Encrypt(text, Secret string) (string, error) {
    key := padKey(Secret)
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    plainText := []byte(text)
    cfb := cipher.NewCFBEncrypter(block, bytes)
    cipherText := make([]byte, len(plainText))
    cfb.XORKeyStream(cipherText, plainText)
    return Encoded(cipherText), nil
}

// Decode decodes a base64 string to bytes
func Decode(s string) []byte {
    data, err := base64.StdEncoding.DecodeString(s)
    if err != nil {
        panic(err)
    }
    return data
}

// Decrypt decrypts the given text using the provided secret key
func Decrypt(text, Secret string) (string, error) {
    key := padKey(Secret)
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    cipherText := Decode(text)
    cfb := cipher.NewCFBDecrypter(block, bytes)
    plainText := make([]byte, len(cipherText))
    cfb.XORKeyStream(plainText, cipherText)
    return string(plainText), nil
}

func main() {
    fmt.Println("Do you want to encode or decode a message? (e/d)")
    var choice string
    fmt.Scanln(&choice)

    fmt.Println("Enter the secret key:")
    reader := bufio.NewReader(os.Stdin)
    Secret, _ := reader.ReadString('\n')
    Secret = strings.TrimSpace(Secret)

    if choice == "e" {
        // Handle encryption
        fmt.Println("Type message to encode")
        fmt.Println("-----------------------")
        StringtoEncrypt, _ := reader.ReadString('\n')
        StringtoEncrypt = strings.TrimSpace(StringtoEncrypt)
        encText, err := Encrypt(StringtoEncrypt, Secret)
        if err != nil {
            fmt.Println("error encrypting your classified text: ", err)
        } else {
            fmt.Println("Do you want to save the encoded text to a file? (y/n)")
            var saveToFile string
            fmt.Scanln(&saveToFile)
            if saveToFile == "y" {
                // Save encoded text to file
                fmt.Println("Enter the filename:")
                var filename string
                fmt.Scanln(&filename)
                err = ioutil.WriteFile(filename, []byte(encText), 0644)
                if err != nil {
                    fmt.Println("error writing to file: ", err)
                } else {
                    fmt.Println("Encoded text saved to file:", filename)
                }
            } else {
                // Print encoded text to console
                fmt.Println("Encoded text:", encText)
            }
        }
    } else if choice == "d" {
        // Handle decryption
        fmt.Println("Type message to decode")
        fmt.Println("-----------------------")
        StringtoDecrypt, _ := reader.ReadString('\n')
        StringtoDecrypt = strings.TrimSpace(StringtoDecrypt)
        decText, err := Decrypt(StringtoDecrypt, Secret)
        if err != nil {
            fmt.Println("error decrypting your classified text: ", err)
        } else {
            fmt.Println("Decoded text:", decText)
        }
    }
}
