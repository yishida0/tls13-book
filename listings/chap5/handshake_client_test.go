package tls13

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const handshakeClientTestServerName = "example.test"

type handshakeClientTestKeyLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *handshakeClientTestKeyLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *handshakeClientTestKeyLog) secret(t *testing.T, label string) []byte {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range strings.Split(l.buf.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == label {
			secret, err := hex.DecodeString(fields[2])
			if err != nil {
				t.Fatal(err)
			}
			return secret
		}
	}
	t.Fatalf("key log has no %s", label)
	return nil
}

type handshakeClientTestServer struct {
	addr       string
	cert       *x509.Certificate
	keyLog     *handshakeClientTestKeyLog
	serverName chan string
}

func newHandshakeClientTestServer(t *testing.T) *handshakeClientTestServer {
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
		cert:       cert,
		keyLog:     &handshakeClientTestKeyLog{},
		serverName: make(chan string, 1),
	}
	config := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		KeyLogWriter:     s.keyLog,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			s.serverName <- info.ServerName
			return nil, nil
		},
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
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		tls.Server(raw, config).Handshake()
	}()
	return s
}

func (s *handshakeClientTestServer) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func handshakeClientTestEstablish(t *testing.T, hs *ClientHandshakeState) {
	t.Helper()
	if err := hs.GenerateKeyPair(); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := hs.SendClientHello(); err != nil {
		t.Fatalf("SendClientHello: %v", err)
	}
	if err := hs.ReadServerHello(); err != nil {
		t.Fatalf("ReadServerHello: %v", err)
	}
	if err := hs.ComputeSharedSecret(); err != nil {
		t.Fatalf("ComputeSharedSecret: %v", err)
	}
	hs.EstablishHandshakeKeys()
}

func TestHandshakeClientSendsServerName(t *testing.T) {
	s := newHandshakeClientTestServer(t)
	hs := NewClientHandshakeState(s.dial(t), handshakeClientTestServerName)
	handshakeClientTestEstablish(t, hs)
	select {
	case got := <-s.serverName:
		if got != handshakeClientTestServerName {
			t.Errorf("server saw SNI %q, want %q", got, handshakeClientTestServerName)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not receive ClientHello")
	}
}

func TestHandshakeClientDerivesHandshakeTrafficSecrets(t *testing.T) {
	s := newHandshakeClientTestServer(t)
	hs := NewClientHandshakeState(s.dial(t), handshakeClientTestServerName)
	handshakeClientTestEstablish(t, hs)
	if err := hs.ReadEncryptedExtensions(); err != nil {
		t.Fatalf("ReadEncryptedExtensions: %v", err)
	}
	if want := s.keyLog.secret(t, "CLIENT_HANDSHAKE_TRAFFIC_SECRET"); !bytes.Equal(hs.clientHandshakeTrafficSecret, want) {
		t.Errorf("client handshake traffic secret = %x, want %x", hs.clientHandshakeTrafficSecret, want)
	}
	if want := s.keyLog.secret(t, "SERVER_HANDSHAKE_TRAFFIC_SECRET"); !bytes.Equal(hs.serverHandshakeTrafficSecret, want) {
		t.Errorf("server handshake traffic secret = %x, want %x", hs.serverHandshakeTrafficSecret, want)
	}
}

func TestHandshakeClientDecryptsServerHandshakeMessages(t *testing.T) {
	s := newHandshakeClientTestServer(t)
	hs := NewClientHandshakeState(s.dial(t), handshakeClientTestServerName)
	handshakeClientTestEstablish(t, hs)
	if err := hs.ReadEncryptedExtensions(); err != nil {
		t.Fatalf("ReadEncryptedExtensions: %v", err)
	}
	if err := hs.ReadCertificate(); err != nil {
		t.Fatalf("ReadCertificate: %v", err)
	}
	if err := hs.ReadCertificateVerify(); err != nil {
		t.Fatalf("ReadCertificateVerify: %v", err)
	}
	msg, _, err := hs.c.readHandshake()
	if err != nil {
		t.Fatalf("reading Finished: %v", err)
	}
	if msg.HandshakeType != TypeFinished || len(msg.Body) != 32 {
		t.Errorf("next message = type %d with %d bytes, want Finished with 32 bytes", msg.HandshakeType, len(msg.Body))
	}
}

func TestHandshakeClientRejectsUnexpectedMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		sh := NewHandshake(TypeServerHello, []byte{0x03, 0x03})
		server.Write(NewTLSPlaintext(ContentTypeHandshake, sh.Marshal()).Marshal())
	}()
	hs := &ClientHandshakeState{c: &Conn{conn: client}, transcript: newTranscript()}
	if err := hs.ReadEncryptedExtensions(); err == nil {
		t.Error("reading EncryptedExtensions when ServerHello arrives: want error, got nil")
	}
}
