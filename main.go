package main

import (
	"go-jwt/route"
)

var err error

func main() {

	r := route.SetupRouter()
	//running
	r.Run()
}
