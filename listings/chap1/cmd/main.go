package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
)

type dumpConn struct {
	net.Conn
}

func (c *dumpConn) Write(p []byte) (int, error) {
	fmt.Printf("--> send %d bytes\n", len(p))
	fmt.Print(hex.Dump(p))
	fmt.Println()
	return c.Conn.Write(p)
}

func (c *dumpConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		fmt.Printf("<-- recv %d bytes\n", n)
		fmt.Print(hex.Dump(p[:n]))
		fmt.Println()
	}
	return n, err
}

func main() {
	raw, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		panic(err)
	}
	conn := tls.Client(&dumpConn{Conn: raw}, &tls.Config{
		ServerName: "example.com",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	io.Copy(io.Discard, conn)
}
