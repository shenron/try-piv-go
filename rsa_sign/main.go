package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/tcastelly/try-piv-go/lib"
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

	cert, err := yk.Certificate(piv.SlotAuthentication)
	if err != nil {
		fmt.Println(err)
		return
	}

	key := piv.KeyAuth{
		PIN: pin,
		PINPolicy: piv.PINPolicyOnce,
	}

	priv, err := yk.PrivateKey(piv.SlotAuthentication, cert.PublicKey, key)
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		panic("no public rsa")
	}

	data := sha256.Sum256([]byte("hello"))
	hash := data[:]

  s, ok := priv.(crypto.Signer)
  if !ok {
    fmt.Println("private key didn't implement crypto.Signer")
    return
  }

  out, err := s.Sign(rand.Reader, hash, crypto.SHA256)
  if err != nil {
	  fmt.Printf("signing failed: %v\n", err)
  }
  if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash, out); err != nil {
	  fmt.Printf("failed to verify signature: %v\n", err)
  }

	fmt.Println("done with success")
}
