package tls13

import (
	"fmt"
	"io"
	"net"
)

type Conn struct {
	conn         net.Conn
	config       *Config
	in, out      *recordProtection
	handshakeBuf []byte
	appDataBuf   []byte
}

func (c *Conn) Write(p []byte) (n int, err error) {
	for n < len(p) {
		end := min(n+maxPlaintextLen, len(p))
		if err := c.writeRecord(newTLSPlaintext(contentTypeApplicationData, p[n:end])); err != nil {
			return n, err
		}
		n = end
	}
	return n, nil
}

func (c *Conn) Close() error {
	if c.out != nil {
		alert := &alert{level: alertLevelWarning, description: closeNotify}
		c.writeRecord(newTLSPlaintext(contentTypeAlert, alert.marshal()))
	}
	return c.conn.Close()
}

func (c *Conn) Read(p []byte) (n int, err error) {
	for len(c.appDataBuf) == 0 {
		rec, err := c.readAndDecryptRecord()
		if err != nil {
			return 0, err
		}
		switch rec.contentType {
		case contentTypeApplicationData:
			c.appDataBuf = rec.payload
		case contentTypeHandshake:
		case contentTypeAlert:
			return 0, c.alertError(rec.payload)
		default:
			return 0, fmt.Errorf("tls13: unexpected record type %d", rec.contentType)
		}
	}
	n = copy(p, c.appDataBuf)
	c.appDataBuf = c.appDataBuf[n:]
	return n, nil
}

func (c *Conn) alertError(payload []byte) error {
	alert, err := unmarshalAlert(payload)
	if err != nil {
		return err
	}
	if alert.description == closeNotify {
		return io.EOF
	}
	return alert
}

func (c *Conn) readAndDecryptRecord() (rec *tlsPlaintext, err error) {
	for {
		rec, err = readRecord(c.conn)
		if err != nil {
			return nil, err
		}
		if rec.contentType != contentTypeChangeCipherSpec {
			break
		}
	}
	if c.in == nil {
		return rec, nil
	}
	if rec.contentType != contentTypeApplicationData {
		return nil, fmt.Errorf("tls13: unexpected plaintext record type %d", rec.contentType)
	}
	inner, err := c.in.decrypt(rec)
	if err != nil {
		return nil, err
	}
	return newTLSPlaintext(inner.contentType, inner.content), nil
}

func (c *Conn) readHandshake() (msg *handshake, raw []byte, err error) {
	for !hasCompleteHandshake(c.handshakeBuf) {
		rec, err := c.readAndDecryptRecord()
		if err != nil {
			return nil, nil, err
		}
		switch rec.contentType {
		case contentTypeHandshake:
			c.handshakeBuf = append(c.handshakeBuf, rec.payload...)
		case contentTypeAlert:
			return nil, nil, fmt.Errorf("tls13: received alert record: % x", rec.payload)
		default:
			return nil, nil, fmt.Errorf("tls13: unexpected record type %d during handshake", rec.contentType)
		}
	}
	n := 4 + handshakeBodyLen(c.handshakeBuf)
	raw = c.handshakeBuf[:n]
	c.handshakeBuf = c.handshakeBuf[n:]
	msg, err = unmarshalHandshake(raw)
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

func (c *Conn) writeRecord(rec *tlsPlaintext) (err error) {
	if c.out != nil {
		rec = newTLSPlaintext(contentTypeApplicationData, c.out.encrypt(rec.contentType, rec.payload))
	}
	_, err = c.conn.Write(rec.marshal())
	return err
}
