package main

import (
	"flag"
	"fmt"
	"github.com/pennmanor/iap"
	"log"
)

var target = flag.String("target", "", "Client ID of IAP you are targeting")

func main() {

	flag.Parse()
	fmt.Println(*target)

	token, err := iap.GetTokenFromGCE(*target)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token)
}
