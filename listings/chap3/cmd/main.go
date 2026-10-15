package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"

	"tls13"
)

const (
	serverName = "example.com"
	addr       = "example.com:443"
)

func main() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	var random [32]byte
	rand.Read(random[:])

	ch := tls13.NewClientHello(random, []tls13.Extension{
		tls13.SupportedVersionsExtension(),
		tls13.ServerNameExtension(serverName),
		tls13.SignatureAlgorithmsExtension(),
		tls13.SupportedGroupsExtension(),
		tls13.KeyShareExtension(priv.PublicKey().Bytes()),
	})
	h := tls13.NewHandshake(tls13.TypeClientHello, ch.Marshal())
	rec := tls13.NewTLSPlaintext(tls13.ContentTypeHandshake, h.Marshal())

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	if _, err := conn.Write(rec.Marshal()); err != nil {
		panic(err)
	}

	res, err := tls13.ReadRecord(conn)
	if err != nil {
		panic(err)
	}
	msg, err := tls13.UnmarshalHandshake(res.Payload)
	if err != nil {
		panic(err)
	}
	if msg.HandshakeType != tls13.TypeServerHello {
		panic("tls13: expected ServerHello")
	}
	sh, err := tls13.UnmarshalServerHello(msg.Body)
	if err != nil {
		panic(err)
	}

	if sh.CipherSuite != tls13.TLS_AES_128_GCM_SHA256 {
		panic("tls13: server selected an unsupported cipher suite")
	}
	version, ok := sh.SelectedVersion()
	if !ok || version != tls13.TLS_VERSION_1_3 {
		panic("tls13: server did not negotiate TLS 1.3")
	}
	group, keyExchange, ok := sh.KeyShare()
	if !ok || group != tls13.X25519 {
		panic("tls13: server did not send an X25519 key share")
	}

	fmt.Printf("cipher suite = %#04x\n", uint16(sh.CipherSuite))
	fmt.Printf("version      = %#04x\n", uint16(version))
	fmt.Printf("group        = %#04x\n", uint16(group))
	fmt.Printf("server key   = %x\n", keyExchange)

	serverPub, err := ecdh.X25519().NewPublicKey(keyExchange)
	if err != nil {
		panic(err)
	}
	shared, err := priv.ECDH(serverPub)
	if err != nil {
		panic(err)
	}
	fmt.Printf("shared secret = %x\n", shared)
}
