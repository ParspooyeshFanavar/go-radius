package radius_test

import (
	"context"
	"log"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/rfc2865"
)

var (
	ClientUsername = "tim"
	ClientPassword = "12345"
)

func Example_client() {
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	rfc2865.UserName_SetString(packet, ClientUsername)
	rfc2865.UserPassword_SetString(packet, ClientPassword)
	response, err := radius.Exchange(context.Background(), packet, "localhost:1812")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Code:", response.Code)
}
