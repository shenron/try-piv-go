package main

import (
	"crypto/tls"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/tcastelly/try-piv-go/lib"
	"log"
	"net/http"
	"os"
)

func main() {
	pin, err := lib.AskPin()
	if err != nil {
		fmt.Println(err)
		return
	}

	yk, close, err := lib.GetYubikey()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer close()

	slot := piv.SlotAuthentication

	cert, err := yk.Certificate(slot)
	if err != nil {
		fmt.Println(err)
		return
	}

	priv, err := yk.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{
		PIN:       pin,
		PINPolicy: piv.PINPolicyOnce,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// define http server
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
		writer.Write([]byte("hello world"))
	})

	logger := log.New(os.Stdout, "http: ", log.LstdFlags)

	s := &http.Server{
		Addr:     ":1443",
		ErrorLog: logger,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  priv,
				},
			},
		},
		Handler: mux,
	}

	e := s.ListenAndServe()
	if e != nil {
		panic(e)
	}
}
