package main

import (
	"net"

	"tls13"
)

const (
	serverName = "example.com"
	addr       = "example.com:443"
)

func main() {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	hs := tls13.NewClientHandshakeState(conn, serverName)
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
	if err := hs.ReadCertificateVerify(); err != nil {
		panic(err)
	}
}
