package tls13

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	errPayloadTooLarge      = errors.New("tls13: payload too large")
	errInnerPlaintextNoType = errors.New("tls13: inner plaintext missing content type")
)

type tlsPlaintext struct {
	contentType contentType
	version     tlsVersion
	length      uint16
	payload     []byte
}

func newTLSPlaintext(contentType contentType, fragment []byte) *tlsPlaintext {
	return &tlsPlaintext{
		contentType: contentType,
		version:     tls_version_1_2,
		length:      uint16(len(fragment)),
		payload:     fragment,
	}
}

func (p *tlsPlaintext) marshal() []byte {
	buf := make([]byte, 5, 5+len(p.payload))
	buf[0] = byte(p.contentType)
	binary.BigEndian.PutUint16(buf[1:], uint16(p.version))
	binary.BigEndian.PutUint16(buf[3:], p.length)
	return append(buf, p.payload...)
}

func readRecord(r io.Reader) (*tlsPlaintext, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(hdr[3:])
	if int(length) > maxPayloadLen {
		return nil, errPayloadTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &tlsPlaintext{
		contentType: contentType(hdr[0]),
		version:     tlsVersion(binary.BigEndian.Uint16(hdr[1:])),
		length:      length,
		payload:     payload,
	}, nil
}

type tlsInnerPlaintext struct {
	content     []byte
	contentType contentType
}

func (p *tlsInnerPlaintext) marshal() []byte {
	buf := make([]byte, 0, len(p.content)+1)
	buf = append(buf, p.content...)
	return append(buf, byte(p.contentType))
}

func parseTLSInnerPlaintext(data []byte) (*tlsInnerPlaintext, error) {
	i := len(data) - 1
	for i >= 0 && data[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, errInnerPlaintextNoType
	}
	return &tlsInnerPlaintext{
		content:     data[:i],
		contentType: contentType(data[i]),
	}, nil
}
