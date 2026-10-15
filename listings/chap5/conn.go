package tls13

import (
	"fmt"
	"net"
)

type Conn struct {
	conn         net.Conn
	in           *recordProtection
	handshakeBuf []byte
}

func (c *Conn) readAndDecryptRecord() (rec *TLSPlaintext, err error) {
	for {
		rec, err = ReadRecord(c.conn)
		if err != nil {
			return nil, err
		}
		if rec.Type != ContentTypeChangeCipherSpec {
			break
		}
	}
	if c.in == nil {
		return rec, nil
	}
	if rec.Type != ContentTypeApplicationData {
		return nil, fmt.Errorf("tls13: unexpected plaintext record type %d", rec.Type)
	}
	inner, err := c.in.decrypt(rec)
	if err != nil {
		return nil, err
	}
	return NewTLSPlaintext(inner.contentType, inner.content), nil
}

func (c *Conn) readHandshake() (msg *Handshake, raw []byte, err error) {
	for !hasCompleteHandshake(c.handshakeBuf) {
		rec, err := c.readAndDecryptRecord()
		if err != nil {
			return nil, nil, err
		}
		switch rec.Type {
		case ContentTypeHandshake:
			c.handshakeBuf = append(c.handshakeBuf, rec.Payload...)
		case ContentTypeAlert:
			return nil, nil, fmt.Errorf("tls13: received alert record: % x", rec.Payload)
		default:
			return nil, nil, fmt.Errorf("tls13: unexpected record type %d during handshake", rec.Type)
		}
	}
	n := 4 + handshakeBodyLen(c.handshakeBuf)
	raw = c.handshakeBuf[:n]
	c.handshakeBuf = c.handshakeBuf[n:]
	msg, err = UnmarshalHandshake(raw)
	if err != nil {
		return nil, nil, err
	}
	return msg, raw, nil
}

func hasCompleteHandshake(buf []byte) (ok bool) {
	return len(buf) >= 4 && len(buf) >= 4+handshakeBodyLen(buf)
}

func handshakeBodyLen(buf []byte) (bodyLen int) {
	return int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
}
