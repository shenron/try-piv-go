package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/tcastelly/try-piv-go/lib"
)

// https://github.com/go-piv/piv-go/blob/master/piv/key_test.go#L335
// https://github.com/keybase/go-crypto/blob/master/openpgp/write.go#L204-L209
// https://github.com/keybase/go-crypto/issues/72
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

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Printf("no public rsa")
		return
	}

	data := []byte("hello")
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, data)
	if err != nil {
		fmt.Printf("encryption failed: %v\n", err)
		return
	}

	priv, err := yk.PrivateKey(piv.SlotAuthentication, rsaPub, piv.KeyAuth{
		PIN:       pin,
		PINPolicy: piv.PINPolicyOnce,
	})
	if err != nil {
		fmt.Printf("getting private key: %v", err)
		return
	}
	d, ok := priv.(crypto.Decrypter)
	if !ok {
		fmt.Printf("private key didn't implement crypto.Decypter")
		return
	}
	got, err := d.Decrypt(rand.Reader, ct, nil)
	if err != nil {
		fmt.Printf("decryption failed: %v", err)
		return
	}
	if !bytes.Equal(data, got) {
		fmt.Printf("decrypt, got=%q, want=%q\n", got, data)
		return
	}
	fmt.Println("done with success")
}
