<img src="internal/radius.svg" width="250" align="right">

# radius

a Go (golang) [RADIUS](https://tools.ietf.org/html/rfc2865) client and server implementation

[![GoDoc](https://godoc.org/github.com/ParspooyeshFanavar/go-radius?status.svg)](https://godoc.org/github.com/ParspooyeshFanavar/go-radius)
[![CircleCI](https://circleci.com/gh/layeh/radius/tree/master.svg?style=shield)](https://circleci.com/gh/layeh/radius/tree/master)

## Installation

    go get -u github.com/ParspooyeshFanavar/go-radius

## Client example

```go
package main

import (
	"context"
	"log"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/rfc2865"
)

func main() {
	packet := radius.New(radius.CodeAccessRequest, []byte(`secret`))
	rfc2865.UserName_SetString(packet, "tim")
	rfc2865.UserPassword_SetString(packet, "12345")
	response, err := radius.Exchange(context.Background(), packet, "localhost:1812")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Code:", response.Code)
}
```

## Server example

```go
package main

import (
	"log"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/rfc2865"
)

func main() {
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		username := rfc2865.UserName_GetString(r.Packet)
		password := rfc2865.UserPassword_GetString(r.Packet)

		var code radius.Code
		if username == "tim" && password == "12345" {
			code = radius.CodeAccessAccept
		} else {
			code = radius.CodeAccessReject
		}
		log.Printf("Writing %v to %v", code, r.RemoteAddr)
		w.Write(r.Response(code))
	}

	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(`secret`)),
	}

	log.Printf("Starting server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
```

## RADIUS Dictionaries

Included in this package is the command line program `radius-dict-gen`. It can be installed with:

    go get -u github.com/ParspooyeshFanavar/go-radius/cmd/radius-dict-gen

Given a FreeRADIUS dictionary, the program will generate helper functions and types for reading and manipulating RADIUS attributes in a packet. It is recommended that generated code be used for any RADIUS dictionary you would like to consume.

Included in this repository are sub-packages of generated helpers for commonly used RADIUS attributes, including [`rfc2865`](https://godoc.org/github.com/ParspooyeshFanavar/go-radius/rfc2865) and [`rfc2866`](https://godoc.org/github.com/ParspooyeshFanavar/go-radius/rfc2866).

## License

MPL 2.0

## Author

Tim Cooper (<tim.cooper@layeh.com>)
