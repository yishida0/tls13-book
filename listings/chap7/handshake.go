package tls13

import "errors"

var errHandshakeTooShort = errors.New("tls13: handshake message too short")

type handshake struct {
	handshakeType handshakeType
	length        [3]byte
	body          []byte
}

func newHandshake(handshakeType handshakeType, body []byte) *handshake {
	length := len(body)
	return &handshake{
		handshakeType: handshakeType,
		length:        [3]byte{byte(length >> 16), byte(length >> 8), byte(length)},
		body:          body,
	}
}

func (h *handshake) marshal() []byte {
	buf := make([]byte, 4, 4+len(h.body))
	buf[0] = byte(h.handshakeType)
	copy(buf[1:], h.length[:])
	return append(buf, h.body...)
}

func unmarshalHandshake(data []byte) (*handshake, error) {
	if len(data) < 4 {
		return nil, errHandshakeTooShort
	}
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) != 4+length {
		return nil, errors.New("tls13: handshake length mismatch")
	}
	return &handshake{
		handshakeType: handshakeType(data[0]),
		length:        [3]byte{data[1], data[2], data[3]},
		body:          data[4:],
	}, nil
}
