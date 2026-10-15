package tls13

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

const clientTestServerName = "example.test"

type clientTestCountingConn struct {
	net.Conn
	n atomic.Int64
}

func (c *clientTestCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

type clientTestResult struct {
	handshakeErr error
	received     []byte
	closeErr     error
	closeBytes   int64
}

type clientTestServer struct {
	addr   string
	roots  *x509.CertPool
	result chan clientTestResult
}

func newClientTestServer(t *testing.T) *clientTestServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: clientTestServerName},
		DNSNames:              []string{clientTestServerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s := &clientTestServer{roots: x509.NewCertPool(), result: make(chan clientTestResult, 1)}
	s.roots.AddCert(cert)
	config := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s.addr = ln.Addr().String()
	go func() {
		var r clientTestResult
		defer func() { s.result <- r }()
		raw, err := ln.Accept()
		if err != nil {
			r.handshakeErr = err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		counting := &clientTestCountingConn{Conn: raw}
		conn := tls.Server(counting, config)
		if r.handshakeErr = conn.Handshake(); r.handshakeErr != nil {
			return
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			r.closeErr = err
			return
		}
		r.received = buf[:n]
		if _, err := conn.Write(r.received); err != nil {
			r.closeErr = err
			return
		}
		before := counting.n.Load()
		_, r.closeErr = conn.Read(buf)
		r.closeBytes = counting.n.Load() - before
	}()
	return s
}

func (s *clientTestServer) wait(t *testing.T) clientTestResult {
	t.Helper()
	select {
	case r := <-s.result:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("server did not finish")
		return clientTestResult{}
	}
}

func TestClientDialWriteReadClose(t *testing.T) {
	s := newClientTestServer(t)
	conn, err := Dial("tcp", s.addr, &Config{ServerName: clientTestServerName, RootCAs: s.roots})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := []byte("GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(request))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, request) {
		t.Errorf("Read = %q, want the echoed request %q", got, request)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r := s.wait(t)
	if r.handshakeErr != nil {
		t.Fatalf("server handshake: %v", r.handshakeErr)
	}
	if !bytes.Equal(r.received, request) {
		t.Errorf("server received %q, want %q", r.received, request)
	}
	if r.closeErr != io.EOF {
		t.Errorf("server read after Close = %v, want io.EOF", r.closeErr)
	}
	if r.closeBytes != 5+2+1+16 {
		t.Errorf("server received %d bytes on Close, want one encrypted close_notify record (24 bytes)", r.closeBytes)
	}
}

func TestClientDialRejectsInvalidCertificate(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		trusted    bool
	}{
		{"untrusted root", clientTestServerName, false},
		{"wrong server name", "other.test", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newClientTestServer(t)
			roots := x509.NewCertPool()
			if tt.trusted {
				roots = s.roots
			}
			conn, err := Dial("tcp", s.addr, &Config{ServerName: tt.serverName, RootCAs: roots})
			if err == nil {
				conn.Close()
				t.Fatal("Dial succeeded, want a certificate verification error")
			}
			if conn != nil {
				t.Error("Dial returned a non-nil Conn with an error")
			}
			r := s.wait(t)
			if r.handshakeErr == nil {
				t.Error("server handshake succeeded")
			}
			if errors.Is(r.handshakeErr, os.ErrDeadlineExceeded) {
				t.Error("Dial did not close the TCP connection after the failed handshake")
			}
		})
	}
}

func TestClientDialReportsConnectionError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if _, err := Dial("tcp", addr, &Config{ServerName: clientTestServerName}); err == nil {
		t.Fatal("Dial succeeded without a listening server")
	}
}
