package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/tcastelly/try-piv-go/lib"
	"math/big"
	"time"
)

func main() {
	yk, close, err := lib.GetYubikey()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer close()
	slot := piv.SlotCardAuthentication

	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("generating ca private: %v", err)
	}

	notAfter := time.Now().AddDate(1, 0, 0)

	// Generate a self-signed certificate
	caTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "localhost"},
		SerialNumber:          big.NewInt(100),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPriv.Public(), caPriv)
	if err != nil {
		fmt.Printf("generating self-signed certificate: %v", err)
		return
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		fmt.Printf("parsing ca cert: %v", err)
		return
	}

	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		TouchPolicy: piv.TouchPolicyNever,
		PINPolicy:   piv.PINPolicyNever,
	}

	pub, err := yk.GenerateKey(piv.DefaultManagementKey, slot, key)
	if err != nil {
		fmt.Printf("generating key: %v\n", err)
	}

	cliTmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "localhost"},
		SerialNumber: big.NewInt(101),
		NotBefore:    time.Now(),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliCertDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, pub, caPriv)
	if err != nil {
		fmt.Printf("creating client cert: %v", err)
		return
	}
	cliCert, err := x509.ParseCertificate(cliCertDER)
	if err != nil {
		fmt.Errorf("parsing cli cert: %v", err)
		return
	}
	if err := yk.SetCertificate(piv.DefaultManagementKey, slot, cliCert); err != nil {
		fmt.Printf("storing client cert: %v", err)
		return
	}
	gotCert, err := yk.Certificate(slot)
	if err != nil {
		fmt.Printf("getting client cert: %v", err)
		return
	}
	if !bytes.Equal(gotCert.Raw, cliCert.Raw) {
		fmt.Printf("stored cert didn't match cert retrieved")
		return
	}
}