package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"tls13"
)

const (
	serverName = "example.com"
	addr       = "example.com:443"
)

var signatureSchemeNames = map[tls13.SignatureScheme]string{
	tls13.RSA_PKCS1_SHA256:       "rsa_pkcs1_sha256",
	tls13.ECDSA_SECP256R1_SHA256: "ecdsa_secp256r1_sha256",
	tls13.ECDSA_SECP384R1_SHA384: "ecdsa_secp384r1_sha384",
	tls13.RSA_PSS_RSAE_SHA256:    "rsa_pss_rsae_sha256",
	tls13.RSA_PSS_RSAE_SHA384:    "rsa_pss_rsae_sha384",
	tls13.RSA_PSS_RSAE_SHA512:    "rsa_pss_rsae_sha512",
}

func main() {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	hs := tls13.NewClientHandshakeState(conn, serverName, nil)
	if err := hs.GenerateKeyPair(); err != nil {
		panic(err)
	}
	if err := hs.SendClientHello(); err != nil {
		panic(err)
	}
	if err := hs.ReadServerHello(); err != nil {
		panic(err)
	}
	if err := hs.ComputeSharedSecret(); err != nil {
		panic(err)
	}
	hs.EstablishHandshakeKeys()
	if err := hs.ReadEncryptedExtensions(); err != nil {
		panic(err)
	}
	if err := hs.ReadCertificate(); err != nil {
		panic(err)
	}
	if err := hs.VerifyCertificate(); err != nil {
		panic(err)
	}
	if err := hs.ReadCertificateVerify(); err != nil {
		panic(err)
	}
	if err := hs.VerifyCertificateVerify(); err != nil {
		panic(err)
	}

	fmt.Println("received certificates:")
	for i, cert := range hs.PeerCertificates {
		fmt.Printf("  [%d] subject=%s\n", i, cert.Subject)
		fmt.Printf("      issuer=%s\n", cert.Issuer)
		fmt.Printf("      valid=%s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		if len(cert.DNSNames) > 0 {
			fmt.Printf("      SAN=%s\n", strings.Join(cert.DNSNames, ", "))
		}
	}

	fmt.Println("verified chain:")
	for i, cert := range hs.VerifiedChains[0] {
		from := "trust store"
		for _, sent := range hs.PeerCertificates {
			if bytes.Equal(sent.Raw, cert.Raw) {
				from = "sent by server"
			}
		}
		fmt.Printf("  [%d] %s (%s)\n", i, cert.Subject, from)
	}
	fmt.Printf("hostname %q matches the certificate\n", serverName)

	cv := hs.PeerCertificateVerify
	fmt.Printf("CertificateVerify: algorithm=%s (%#04x), signature=%d bytes, verified with the server public key\n",
		signatureSchemeNames[cv.Algorithm], uint16(cv.Algorithm), len(cv.Signature))
}
