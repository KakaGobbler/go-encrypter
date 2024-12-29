package main

import (
	"fmt"

	"github.com/thanhpk/randstr"
)

func main() {
	MyString := randstr.String(20)
	fmt.Println(MyString)
}
