package main

import (
	"encoding/base64"
	"fmt"
)

func main() {

	fmt.Println("input: ")
	var wrd string

	fmt.Scanln(&wrd)

	fmt.Println("Encoded:")
	StringToEncode := wrd

	Encoding := base64.StdEncoding.EncodeToString([]byte(StringToEncode))
	fmt.Println(Encoding)
}
