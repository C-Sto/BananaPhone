package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	CERT_STORE_OPEN_EXISTING = 0x00004000
	CERT_STORE_PROV_SYSTEM   = 10 // CERT_STORE_PROV_SYSTEM
)

const (
	//this is stupid. Why is it left shifting by 16? I'm sure there is a reason. There must be.
	_ = (iota << 16)
	CERT_SYSTEM_STORE_CURRENT_USER
	CERT_SYSTEM_STORE_LOCAL_MACHINE
	CERT_SYSTEM_STORE_CURRENT_SERVICE
	CERT_SYSTEM_STORE_SERVICES
	CERT_SYSTEM_STORE_USERS
	CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY
	CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
	CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE
)

func main() {
	fmt.Println("EXTREMELY BIG WARNING - THIS WILL GENERATE AND ADD A CERTIFICATE TO THE ROOT MACHINE STORE WHICH IS VERY BAD IF YOU DONT REALLY KNOW WHAT YOU ARE DOING")
	panic("I agree, I have no idea what I'm doing")

	//This probably shouldn't be in the bananaphone repo, but eventually I'd like to have an example of doing this with no API calls. One day.
	store, e := syscall.CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
		(CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ROOT"))))
	if e != nil {
		panic(e)
	}
	crt := newCert()
	context, e := syscall.CertCreateCertificateContext(1, &crt[0], uint32(len(crt)))
	if e != nil {
		panic(e)
	}
	fmt.Println(store, context, e)
	fmt.Println("check your root CA for machine for certificate details as in newCert()")
}

//repurposed https://github.com/Ne0nd0g/merlin/blob/master/test/testServer/main.go#L191
func newCert() []byte {

	//generate a garbage certificate, with some true facts
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	tpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "127.0.0.1",
			Organization: []string{"Joey is the best hacker in Hackers"},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"127.0.0.1", "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute * 20),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth | x509.ExtKeyUsageCodeSigning}, //codesigning is the important part here
		BasicConstraintsValid: true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	crtBytes, e := x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
	if e != nil {
		panic(e)
	}

	return crtBytes
}
