package tls13

import "errors"

var errHandshakeTooShort = errors.New("tls13: handshake message too short")

type Handshake struct {
	HandshakeType HandshakeType
	Length        [3]byte
	Body          []byte
}

func NewHandshake(handshakeType HandshakeType, body []byte) *Handshake {
	length := len(body)
	return &Handshake{
		HandshakeType: handshakeType,
		Length:        [3]byte{byte(length >> 16), byte(length >> 8), byte(length)},
		Body:          body,
	}
}

func (h *Handshake) Marshal() []byte {
	buf := make([]byte, 4, 4+len(h.Body))
	buf[0] = byte(h.HandshakeType)
	copy(buf[1:], h.Length[:])
	return append(buf, h.Body...)
}

func UnmarshalHandshake(data []byte) (*Handshake, error) {
	if len(data) < 4 {
		return nil, errHandshakeTooShort
	}
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) != 4+length {
		return nil, errors.New("tls13: handshake length mismatch")
	}
	return &Handshake{
		HandshakeType: HandshakeType(data[0]),
		Length:        [3]byte{data[1], data[2], data[3]},
		Body:          data[4:],
	}, nil
}
