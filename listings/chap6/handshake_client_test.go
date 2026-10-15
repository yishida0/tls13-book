package tls13

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	addr   string
	cert   *x509.Certificate
	roots  *x509.CertPool
	keyLog *handshakeClientTestKeyLog
}

func newHandshakeClientTestServer(t *testing.T, key crypto.Signer) *handshakeClientTestServer {
	t.Helper()
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
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s := &handshakeClientTestServer{
		cert:   cert,
		roots:  x509.NewCertPool(),
		keyLog: &handshakeClientTestKeyLog{},
	}
	s.roots.AddCert(cert)
	config := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
		KeyLogWriter:     s.keyLog,
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

func handshakeClientTestECDSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func handshakeClientTestRSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
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
	if err := hs.ReadEncryptedExtensions(); err != nil {
		t.Fatalf("ReadEncryptedExtensions: %v", err)
	}
}

func TestHandshakeClientDerivesHandshakeTrafficSecrets(t *testing.T) {
	s := newHandshakeClientTestServer(t, handshakeClientTestECDSAKey(t))
	hs := NewClientHandshakeState(s.dial(t), handshakeClientTestServerName, s.roots)
	handshakeClientTestEstablish(t, hs)
	if want := s.keyLog.secret(t, "CLIENT_HANDSHAKE_TRAFFIC_SECRET"); !bytes.Equal(hs.clientHandshakeTrafficSecret, want) {
		t.Errorf("client handshake traffic secret = %x, want %x", hs.clientHandshakeTrafficSecret, want)
	}
	if want := s.keyLog.secret(t, "SERVER_HANDSHAKE_TRAFFIC_SECRET"); !bytes.Equal(hs.serverHandshakeTrafficSecret, want) {
		t.Errorf("server handshake traffic secret = %x, want %x", hs.serverHandshakeTrafficSecret, want)
	}
}

func TestHandshakeClientVerifiesServerCertificate(t *testing.T) {
	tests := []struct {
		name      string
		key       func(*testing.T) crypto.Signer
		algorithm SignatureScheme
	}{
		{"ECDSA", handshakeClientTestECDSAKey, ECDSA_SECP256R1_SHA256},
		{"RSA", handshakeClientTestRSAKey, RSA_PSS_RSAE_SHA256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newHandshakeClientTestServer(t, tt.key(t))
			hs := NewClientHandshakeState(s.dial(t), handshakeClientTestServerName, s.roots)
			handshakeClientTestEstablish(t, hs)
			if err := hs.ReadCertificate(); err != nil {
				t.Fatalf("ReadCertificate: %v", err)
			}
			if err := hs.VerifyCertificate(); err != nil {
				t.Fatalf("VerifyCertificate: %v", err)
			}
			if err := hs.ReadCertificateVerify(); err != nil {
				t.Fatalf("ReadCertificateVerify: %v", err)
			}
			if err := hs.VerifyCertificateVerify(); err != nil {
				t.Fatalf("VerifyCertificateVerify: %v", err)
			}
			certs := hs.PeerCertificates
			if len(certs) != 1 || !certs[0].Equal(s.cert) {
				t.Errorf("PeerCertificates = %v, want the server certificate", certs)
			}
			chains := hs.VerifiedChains
			if len(chains) == 0 || len(chains[0]) == 0 || !chains[0][0].Equal(s.cert) {
				t.Errorf("VerifiedChains = %v, want a chain starting with the server certificate", chains)
			}
			cv := hs.PeerCertificateVerify
			if cv == nil {
				t.Fatal("PeerCertificateVerify = nil")
			}
			if cv.Algorithm != tt.algorithm {
				t.Errorf("CertificateVerify algorithm = %#04x, want %#04x", uint16(cv.Algorithm), uint16(tt.algorithm))
			}
			msg, _, err := hs.c.readHandshake()
			if err != nil {
				t.Fatalf("reading Finished: %v", err)
			}
			if msg.HandshakeType != TypeFinished {
				t.Fatalf("next message type = %d, want %d", msg.HandshakeType, TypeFinished)
			}
			mac := hmac.New(sha256.New, hkdfExpandLabel(hs.serverHandshakeTrafficSecret, "finished", nil, sha256.Size))
			mac.Write(hs.transcript.sum())
			if !hmac.Equal(msg.Body, mac.Sum(nil)) {
				t.Error("server Finished does not match the transcript through CertificateVerify")
			}
		})
	}
}

func TestHandshakeClientRejectsInvalidCertificate(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		roots      func(*handshakeClientTestServer) *x509.CertPool
	}{
		{"untrusted root", handshakeClientTestServerName, func(*handshakeClientTestServer) *x509.CertPool { return x509.NewCertPool() }},
		{"wrong server name", "other.test", func(s *handshakeClientTestServer) *x509.CertPool { return s.roots }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newHandshakeClientTestServer(t, handshakeClientTestECDSAKey(t))
			hs := NewClientHandshakeState(s.dial(t), tt.serverName, tt.roots(s))
			handshakeClientTestEstablish(t, hs)
			if err := hs.ReadCertificate(); err != nil {
				t.Fatalf("ReadCertificate: %v", err)
			}
			if err := hs.VerifyCertificate(); err == nil {
				t.Fatal("VerifyCertificate succeeded, want a verification error")
			}
			if hs.VerifiedChains != nil {
				t.Error("chains were stored even though verification failed")
			}
		})
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
