package tls13

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

const (
	handshakeTestServerHello = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
	handshakeTestFinished    = "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
)

func TestHandshakeNew(t *testing.T) {
	tests := []struct {
		name    string
		bodyLen int
		want    [3]byte
	}{
		{"empty", 0, [3]byte{0x00, 0x00, 0x00}},
		{"one byte", 1, [3]byte{0x00, 0x00, 0x01}},
		{"two bytes length", 0x0102, [3]byte{0x00, 0x01, 0x02}},
		{"three bytes length", 0x010203, [3]byte{0x01, 0x02, 0x03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := make([]byte, tt.bodyLen)
			h := newHandshake(typeFinished, body)
			if h.handshakeType != typeFinished {
				t.Errorf("HandshakeType = %d, want %d", h.handshakeType, typeFinished)
			}
			if h.length != tt.want {
				t.Errorf("Length = %x, want %x", h.length, tt.want)
			}
			if len(h.body) != tt.bodyLen {
				t.Errorf("len(Body) = %d, want %d", len(h.body), tt.bodyLen)
			}
		})
	}
}

func TestHandshakeMarshal(t *testing.T) {
	tests := []struct {
		name string
		typ  handshakeType
		msg  string
	}{
		{"RFC 8448 ServerHello", typeServerHello, handshakeTestServerHello},
		{"RFC 8448 server Finished", typeFinished, handshakeTestFinished},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, _ := hex.DecodeString(tt.msg)
			got := newHandshake(tt.typ, want[4:]).marshal()
			if !bytes.Equal(got, want) {
				t.Errorf("Marshal() =\n%x\nwant\n%x", got, want)
			}
		})
	}
}

func TestHandshakeUnmarshal(t *testing.T) {
	tests := []struct {
		name       string
		msg        string
		wantType   handshakeType
		wantLength [3]byte
	}{
		{"RFC 8448 ServerHello", handshakeTestServerHello, typeServerHello, [3]byte{0x00, 0x00, 0x56}},
		{"RFC 8448 server Finished", handshakeTestFinished, typeFinished, [3]byte{0x00, 0x00, 0x20}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.msg)
			h, err := unmarshalHandshake(data)
			if err != nil {
				t.Fatalf("UnmarshalHandshake() error = %v", err)
			}
			if h.handshakeType != tt.wantType {
				t.Errorf("HandshakeType = %d, want %d", h.handshakeType, tt.wantType)
			}
			if h.length != tt.wantLength {
				t.Errorf("Length = %x, want %x", h.length, tt.wantLength)
			}
			if !bytes.Equal(h.body, data[4:]) {
				t.Errorf("Body =\n%x\nwant\n%x", h.body, data[4:])
			}
		})
	}
}

func TestHandshakeUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr error
	}{
		{"empty", "", errHandshakeTooShort},
		{"header only 3 bytes", "140000", errHandshakeTooShort},
		{"body shorter than length", "1400000301", nil},
		{"body longer than length", "140000010102", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.data)
			h, err := unmarshalHandshake(data)
			if err == nil {
				t.Fatalf("UnmarshalHandshake(%x) = %+v, want error", data, h)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandshakeUnmarshalLongBody(t *testing.T) {
	for _, n := range []int{0x0102, 0x010203} {
		body := bytes.Repeat([]byte{0xab}, n)
		data := append([]byte{byte(typeCertificate), byte(n >> 16), byte(n >> 8), byte(n)}, body...)
		h, err := unmarshalHandshake(data)
		if err != nil {
			t.Fatalf("UnmarshalHandshake(header %x) error = %v", data[:4], err)
		}
		if h.handshakeType != typeCertificate || len(h.body) != n || !bytes.Equal(h.length[:], data[1:4]) {
			t.Errorf("UnmarshalHandshake(header %x) = {type %d, length %x, len(body) %d}, want {%d, %x, %d}", data[:4], h.handshakeType, h.length, len(h.body), typeCertificate, data[1:4], n)
		}
	}
}
