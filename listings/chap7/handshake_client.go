package tls13

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
)

type clientHandshakeState struct {
	c *Conn

	transcript *transcript

	privateKey      *ecdh.PrivateKey
	serverPublicKey []byte
	sharedSecret    []byte

	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
	handshakeSecret              []byte

	peerCertificates                []*x509.Certificate
	peerCertificateVerify           *certificateVerify
	certificateVerifyTranscriptHash []byte
}

func (c *Conn) handshake() error {
	hs := &clientHandshakeState{
		c:          c,
		transcript: newTranscript(),
	}
	if err := hs.generateKeyPair(); err != nil {
		return err
	}
	if err := hs.sendClientHello(); err != nil {
		return err
	}
	if err := hs.readServerHello(); err != nil {
		return err
	}
	if err := hs.computeSharedSecret(); err != nil {
		return err
	}
	hs.establishHandshakeKeys()
	if err := hs.readEncryptedExtensions(); err != nil {
		return err
	}
	if err := hs.readCertificate(); err != nil {
		return err
	}
	if err := hs.verifyCertificate(); err != nil {
		return err
	}
	if err := hs.readCertificateVerify(); err != nil {
		return err
	}
	if err := hs.verifyCertificateVerify(); err != nil {
		return err
	}
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	if err := hs.writeClientFinished(); err != nil {
		return err
	}
	hs.switchToApplicationKeys()
	return nil
}

func (hs *clientHandshakeState) generateKeyPair() error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	hs.privateKey = privateKey
	return nil
}

func (hs *clientHandshakeState) sendClientHello() error {
	var random [clientRandomLength]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}

	ch := newClientHello(random, []extension{
		supportedVersionsExtension(),
		serverNameExtension(hs.c.config.ServerName),
		signatureAlgorithmsExtension(),
		supportedGroupsExtension(),
		keyShareExtension(hs.privateKey.PublicKey().Bytes()),
	})
	h := newHandshake(typeClientHello, ch.marshal())
	raw := h.marshal()
	if err := hs.c.writeRecord(newTLSPlaintext(contentTypeHandshake, raw)); err != nil {
		return err
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) readServerHello() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeServerHello {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeServerHello, msg.handshakeType)
	}
	sh, err := unmarshalServerHello(msg.body)
	if err != nil {
		return err
	}
	if sh.cipherSuite != tls_aes_128_gcm_sha256 {
		return fmt.Errorf("tls13: server selected unsupported cipher suite %#x", uint16(sh.cipherSuite))
	}
	if v, ok := sh.selectedVersion(); !ok || v != tls_version_1_3 {
		return errors.New("tls13: server did not negotiate TLS 1.3")
	}
	group, serverPublicKey, ok := sh.keyShare()
	if !ok {
		return errors.New("tls13: server did not send a key share")
	}
	if group != x25519 {
		return fmt.Errorf("tls13: server selected unsupported group %#x", uint16(group))
	}
	hs.serverPublicKey = serverPublicKey
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) computeSharedSecret() error {
	serverPub, err := ecdh.X25519().NewPublicKey(hs.serverPublicKey)
	if err != nil {
		return err
	}
	hs.sharedSecret, err = hs.privateKey.ECDH(serverPub)
	return err
}

func (hs *clientHandshakeState) establishHandshakeKeys() {
	hs.handshakeSecret = deriveHandshakeSecret(hs.sharedSecret)
	transcriptHash := hs.transcript.sum()
	hs.clientHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "c hs traffic", transcriptHash)
	hs.serverHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "s hs traffic", transcriptHash)
	hs.c.in = newRecordProtection(hs.serverHandshakeTrafficSecret)
}

func (hs *clientHandshakeState) readEncryptedExtensions() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeEncryptedExtensions {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeEncryptedExtensions, msg.handshakeType)
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) readCertificate() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeCertificate {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeCertificate, msg.handshakeType)
	}
	certificate, err := unmarshalCertificate(msg.body)
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
	hs.peerCertificates = certs
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) verifyCertificate() error {
	certs := hs.peerCertificates
	opts := x509.VerifyOptions{
		DNSName:       hs.c.config.ServerName,
		Roots:         hs.c.config.RootCAs,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("tls13: certificate verification failed: %w", err)
	}
	return nil
}

func (hs *clientHandshakeState) readCertificateVerify() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeCertificateVerify {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeCertificateVerify, msg.handshakeType)
	}
	cv, err := unmarshalCertificateVerify(msg.body)
	if err != nil {
		return err
	}
	hs.peerCertificateVerify = cv
	hs.certificateVerifyTranscriptHash = hs.transcript.sum()
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) verifyCertificateVerify() error {
	return hs.peerCertificateVerify.verify(hs.peerCertificates[0], hs.certificateVerifyTranscriptHash)
}

func (hs *clientHandshakeState) readServerFinished() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeFinished {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeFinished, msg.handshakeType)
	}
	want := finishedVerifyData(hs.serverHandshakeTrafficSecret, hs.transcript.sum())
	if !hmac.Equal(msg.body, want) {
		return errors.New("tls13: invalid server Finished")
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) writeClientFinished() error {
	msg := newHandshake(typeFinished, finishedVerifyData(hs.clientHandshakeTrafficSecret, hs.transcript.sum()))
	hs.c.out = newRecordProtection(hs.clientHandshakeTrafficSecret)
	return hs.c.writeRecord(newTLSPlaintext(contentTypeHandshake, msg.marshal()))
}

func (hs *clientHandshakeState) switchToApplicationKeys() {
	mainSecret := deriveMainSecret(hs.handshakeSecret)
	transcriptHash := hs.transcript.sum()
	hs.c.in = newRecordProtection(deriveSecret(mainSecret, "s ap traffic", transcriptHash))
	hs.c.out = newRecordProtection(deriveSecret(mainSecret, "c ap traffic", transcriptHash))
}
