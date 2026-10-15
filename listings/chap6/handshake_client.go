package tls13

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
)

type ClientHandshakeState struct {
	c          *Conn
	serverName string
	roots      *x509.CertPool

	transcript *transcript

	privateKey      *ecdh.PrivateKey
	serverPublicKey []byte
	sharedSecret    []byte

	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
	handshakeSecret              []byte

	PeerCertificates                []*x509.Certificate
	VerifiedChains                  [][]*x509.Certificate
	PeerCertificateVerify           *CertificateVerify
	certificateVerifyTranscriptHash []byte
}

func NewClientHandshakeState(conn net.Conn, serverName string, roots *x509.CertPool) *ClientHandshakeState {
	return &ClientHandshakeState{
		c:          &Conn{conn: conn},
		serverName: serverName,
		roots:      roots,
		transcript: newTranscript(),
	}
}

func (hs *ClientHandshakeState) GenerateKeyPair() error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	hs.privateKey = privateKey
	return nil
}

func (hs *ClientHandshakeState) SendClientHello() error {
	var random [clientRandomLength]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}

	ch := NewClientHello(random, []Extension{
		SupportedVersionsExtension(),
		ServerNameExtension(hs.serverName),
		SignatureAlgorithmsExtension(),
		SupportedGroupsExtension(),
		KeyShareExtension(hs.privateKey.PublicKey().Bytes()),
	})
	h := NewHandshake(TypeClientHello, ch.Marshal())
	raw := h.Marshal()
	if _, err := hs.c.conn.Write(NewTLSPlaintext(ContentTypeHandshake, raw).Marshal()); err != nil {
		return err
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) ReadServerHello() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeServerHello {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeServerHello, msg.HandshakeType)
	}
	sh, err := UnmarshalServerHello(msg.Body)
	if err != nil {
		return err
	}
	if sh.CipherSuite != TLS_AES_128_GCM_SHA256 {
		return fmt.Errorf("tls13: server selected unsupported cipher suite %#x", uint16(sh.CipherSuite))
	}
	if v, ok := sh.SelectedVersion(); !ok || v != TLS_VERSION_1_3 {
		return errors.New("tls13: server did not negotiate TLS 1.3")
	}
	group, serverPublicKey, ok := sh.KeyShare()
	if !ok {
		return errors.New("tls13: server did not send a key share")
	}
	if group != X25519 {
		return fmt.Errorf("tls13: server selected unsupported group %#x", uint16(group))
	}
	hs.serverPublicKey = serverPublicKey
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) ComputeSharedSecret() error {
	serverPub, err := ecdh.X25519().NewPublicKey(hs.serverPublicKey)
	if err != nil {
		return err
	}
	hs.sharedSecret, err = hs.privateKey.ECDH(serverPub)
	return err
}

func (hs *ClientHandshakeState) EstablishHandshakeKeys() {
	hs.handshakeSecret = deriveHandshakeSecret(hs.sharedSecret)
	transcriptHash := hs.transcript.sum()
	hs.clientHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "c hs traffic", transcriptHash)
	hs.serverHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "s hs traffic", transcriptHash)
	hs.c.in = newRecordProtection(hs.serverHandshakeTrafficSecret)
}

func (hs *ClientHandshakeState) ReadEncryptedExtensions() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeEncryptedExtensions {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeEncryptedExtensions, msg.HandshakeType)
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) ReadCertificate() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeCertificate {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeCertificate, msg.HandshakeType)
	}
	certificate, err := unmarshalCertificate(msg.Body)
	if err != nil {
		return err
	}
	if len(certificate.certificateList) == 0 {
		return errors.New("tls13: server sent no certificates")
	}
	certs := make([]*x509.Certificate, len(certificate.certificateList))
	for i, der := range certificate.certificateList {
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return err
		}
	}
	hs.PeerCertificates = certs
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) VerifyCertificate() error {
	certs := hs.PeerCertificates
	opts := x509.VerifyOptions{
		DNSName:       hs.serverName,
		Roots:         hs.roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	chains, err := certs[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("tls13: certificate verification failed: %w", err)
	}
	hs.VerifiedChains = chains
	return nil
}

func (hs *ClientHandshakeState) ReadCertificateVerify() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeCertificateVerify {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeCertificateVerify, msg.HandshakeType)
	}
	cv, err := UnmarshalCertificateVerify(msg.Body)
	if err != nil {
		return err
	}
	hs.PeerCertificateVerify = cv
	hs.certificateVerifyTranscriptHash = hs.transcript.sum()
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) VerifyCertificateVerify() error {
	return hs.PeerCertificateVerify.Verify(hs.PeerCertificates[0], hs.certificateVerifyTranscriptHash)
}
