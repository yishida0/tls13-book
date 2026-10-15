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

type TLSPlaintext struct {
	Type    ContentType
	Version TLSVersion
	Length  uint16
	Payload []byte
}

func NewTLSPlaintext(contentType ContentType, fragment []byte) *TLSPlaintext {
	return &TLSPlaintext{
		Type:    contentType,
		Version: TLS_VERSION_1_2,
		Length:  uint16(len(fragment)),
		Payload: fragment,
	}
}

func (p *TLSPlaintext) Marshal() []byte {
	buf := make([]byte, 5, 5+len(p.Payload))
	buf[0] = byte(p.Type)
	binary.BigEndian.PutUint16(buf[1:], uint16(p.Version))
	binary.BigEndian.PutUint16(buf[3:], p.Length)
	return append(buf, p.Payload...)
}

func ReadRecord(r io.Reader) (*TLSPlaintext, error) {
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
	return &TLSPlaintext{
		Type:    ContentType(hdr[0]),
		Version: TLSVersion(binary.BigEndian.Uint16(hdr[1:])),
		Length:  length,
		Payload: payload,
	}, nil
}

type tlsInnerPlaintext struct {
	content     []byte
	contentType ContentType
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
		contentType: ContentType(data[i]),
	}, nil
}
