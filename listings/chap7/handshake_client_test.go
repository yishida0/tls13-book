package tls13

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

const handshakeClientTestServerName = "example.test"

type handshakeClientTestServer struct {
	addr       string
	roots      *x509.CertPool
	handshake  chan error
	serverName chan string
	received   chan []byte
}

func newHandshakeClientTestServer(t *testing.T, greeting []byte) *handshakeClientTestServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: handshakeClientTestServerName},
		DNSNames:              []string{handshakeClientTestServerName},
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
	s := &handshakeClientTestServer{
		roots:      x509.NewCertPool(),
		handshake:  make(chan error, 1),
		serverName: make(chan string, 1),
		received:   make(chan []byte, 1),
	}
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
		raw, err := ln.Accept()
		if err != nil {
			s.handshake <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Server(raw, config)
		err = conn.Handshake()
		s.handshake <- err
		if err != nil {
			return
		}
		s.serverName <- conn.ConnectionState().ServerName
		if _, err := conn.Write(greeting); err != nil {
			s.received <- nil
			return
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			s.received <- nil
			return
		}
		s.received <- buf[:n]
	}()
	return s
}

func (s *handshakeClientTestServer) conn(t *testing.T, config *Config) *Conn {
	t.Helper()
	raw, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	return &Conn{conn: raw, config: config}
}

func (s *handshakeClientTestServer) handshakeResult(t *testing.T) error {
	t.Helper()
	select {
	case err := <-s.handshake:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not finish")
		return nil
	}
}

func TestHandshakeClientCompletesHandshake(t *testing.T) {
	s := newHandshakeClientTestServer(t, []byte("hello from server"))
	c := s.conn(t, &Config{ServerName: handshakeClientTestServerName, RootCAs: s.roots})
	if err := c.handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := s.handshakeResult(t); err != nil {
		t.Fatalf("server rejected the handshake: %v", err)
	}
	if got := <-s.serverName; got != handshakeClientTestServerName {
		t.Errorf("server saw SNI %q, want %q", got, handshakeClientTestServerName)
	}
	if c.in == nil || c.out == nil {
		t.Error("handshake did not install application keys on the Conn")
	}
}

func TestHandshakeClientSwitchesToApplicationKeys(t *testing.T) {
	greeting := []byte("hello from server")
	s := newHandshakeClientTestServer(t, greeting)
	c := s.conn(t, &Config{ServerName: handshakeClientTestServerName, RootCAs: s.roots})
	if err := c.handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := s.handshakeResult(t); err != nil {
		t.Fatalf("server rejected the handshake: %v", err)
	}
	var got []byte
	for got == nil {
		rec, err := readRecord(c.conn)
		if err != nil {
			t.Fatalf("ReadRecord: %v", err)
		}
		inner, err := c.in.decrypt(rec)
		if err != nil {
			t.Fatalf("decrypting with application keys: %v", err)
		}
		innerType, content := inner.contentType, inner.content
		if innerType == contentTypeApplicationData {
			got = content
		}
	}
	if !bytes.Equal(got, greeting) {
		t.Errorf("client received %q, want %q", got, greeting)
	}
	request := []byte("hello from client")
	rec := newTLSPlaintext(contentTypeApplicationData, c.out.encrypt(contentTypeApplicationData, request))
	if _, err := c.conn.Write(rec.marshal()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case got := <-s.received:
		if !bytes.Equal(got, request) {
			t.Errorf("server received %q, want %q", got, request)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not answer")
	}
}

func TestHandshakeClientRejectsInvalidCertificate(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		trusted    bool
	}{
		{"untrusted root", handshakeClientTestServerName, false},
		{"wrong server name", "other.test", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newHandshakeClientTestServer(t, nil)
			roots := x509.NewCertPool()
			if tt.trusted {
				roots = s.roots
			}
			c := s.conn(t, &Config{ServerName: tt.serverName, RootCAs: roots})
			if err := c.handshake(); err == nil {
				t.Fatal("handshake succeeded, want a certificate verification error")
			}
			if c.out != nil {
				t.Error("client installed a write key after a failed handshake")
			}
		})
	}
}

func TestHandshakeClientRejectsUnexpectedMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		sh := newHandshake(typeServerHello, []byte{0x03, 0x03})
		server.Write(newTLSPlaintext(contentTypeHandshake, sh.marshal()).marshal())
	}()
	hs := &clientHandshakeState{c: &Conn{conn: client}, transcript: newTranscript()}
	if err := hs.readEncryptedExtensions(); err == nil {
		t.Error("reading EncryptedExtensions when ServerHello arrives: want error, got nil")
	}
}
