package tls13

import (
	"crypto/x509"
	"net"
)

type Config struct {
	ServerName string
	RootCAs    *x509.CertPool
}

func Dial(network, addr string, config *Config) (*Conn, error) {
	raw, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	c := &Conn{conn: raw, config: config}
	if err := c.handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}
