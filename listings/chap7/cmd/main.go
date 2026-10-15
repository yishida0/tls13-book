package main

import (
	"fmt"
	"io"
	"net/url"
	"os"

	"tls13"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tlsclient <https-url>")
		os.Exit(1)
	}
	u, err := url.Parse(os.Args[1])
	if err != nil || u.Scheme != "https" {
		fmt.Fprintln(os.Stderr, "error: https URL required")
		os.Exit(1)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}

	conn, err := tls13.Dial("tcp", u.Hostname()+":"+port, &tls13.Config{ServerName: u.Hostname()})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Hostname()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
