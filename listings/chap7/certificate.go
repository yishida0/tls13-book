package tls13

import (
	"crypto/x509"
	"errors"
	"fmt"
)

type certificate struct {
	certificateList [][]byte
}

func unmarshalCertificate(body []byte) (*certificate, error) {
	malformed := errors.New("tls13: malformed Certificate")

	_, rest, ok := readUint8Prefixed(body)
	if !ok {
		return nil, malformed
	}
	list, rest, ok := readUint24Prefixed(rest)
	if !ok || len(rest) != 0 {
		return nil, malformed
	}

	cert := &certificate{}
	for len(list) > 0 {
		certData, r, ok := readUint24Prefixed(list)
		if !ok {
			return nil, malformed
		}
		_, r, ok = readUint16Prefixed(r)
		if !ok {
			return nil, malformed
		}
		cert.certificateList = append(cert.certificateList, append([]byte{}, certData...))
		list = r
	}
	return cert, nil
}

type certificateVerify struct {
	algorithm signatureScheme
	signature []byte
}

func unmarshalCertificateVerify(body []byte) (*certificateVerify, error) {
	malformed := errors.New("tls13: malformed CertificateVerify")

	algorithm, rest, ok := readUint16(body)
	if !ok {
		return nil, malformed
	}
	signature, rest, ok := readUint16Prefixed(rest)
	if !ok || len(rest) != 0 {
		return nil, malformed
	}
	return &certificateVerify{
		algorithm: signatureScheme(algorithm),
		signature: append([]byte{}, signature...),
	}, nil
}

func (cv *certificateVerify) verify(cert *x509.Certificate, transcriptHash []byte) error {
	content := make([]byte, 0, 64+34+len(transcriptHash))
	for range 64 {
		content = append(content, 0x20)
	}
	content = append(content, "TLS 1.3, server CertificateVerify"...)
	content = append(content, 0)
	content = append(content, transcriptHash...)

	var algorithm x509.SignatureAlgorithm
	switch cv.algorithm {
	case rsa_pss_rsae_sha256:
		algorithm = x509.SHA256WithRSAPSS
	case rsa_pss_rsae_sha384:
		algorithm = x509.SHA384WithRSAPSS
	case rsa_pss_rsae_sha512:
		algorithm = x509.SHA512WithRSAPSS
	case ecdsa_secp256r1_sha256:
		algorithm = x509.ECDSAWithSHA256
	case ecdsa_secp384r1_sha384:
		algorithm = x509.ECDSAWithSHA384
	default:
		return fmt.Errorf("tls13: unsupported signature scheme %#x", uint16(cv.algorithm))
	}
	return cert.CheckSignature(algorithm, content, cv.signature)
}
