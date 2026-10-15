package tls13

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

const (
	recordTestServerHelloRecord = "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
	recordTestClientHelloRecord = "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
)

func TestRecordNewTLSPlaintext(t *testing.T) {
	fragment := []byte{0x01, 0x02, 0x03}
	p := newTLSPlaintext(contentTypeHandshake, fragment)
	if p.contentType != contentTypeHandshake {
		t.Errorf("Type = %d, want %d", p.contentType, contentTypeHandshake)
	}
	if p.version != 0x0303 {
		t.Errorf("Version = %#04x, want 0x0303", uint16(p.version))
	}
	if p.length != 3 {
		t.Errorf("Length = %d, want 3", p.length)
	}
	if !bytes.Equal(p.payload, fragment) {
		t.Errorf("Payload = %x, want %x", p.payload, fragment)
	}
}

func TestRecordMarshal(t *testing.T) {
	sh, _ := hex.DecodeString(recordTestServerHelloRecord)
	if got := newTLSPlaintext(contentTypeHandshake, sh[5:]).marshal(); !bytes.Equal(got, sh) {
		t.Errorf("RFC 8448 ServerHello record:\ngot  %x\nwant %x", got, sh)
	}

	ch, _ := hex.DecodeString(recordTestClientHelloRecord)
	p := &tlsPlaintext{
		contentType: contentTypeHandshake,
		version:     0x0301,
		length:      uint16(len(ch) - 5),
		payload:     ch[5:],
	}
	if got := p.marshal(); !bytes.Equal(got, ch) {
		t.Errorf("RFC 8448 ClientHello record:\ngot  %x\nwant %x", got, ch)
	}

	big := &tlsPlaintext{contentType: contentTypeApplicationData, version: 0x0303, length: 0x1234, payload: make([]byte, 0x1234)}
	if got, want := big.marshal()[:5], []byte{0x17, 0x03, 0x03, 0x12, 0x34}; !bytes.Equal(got, want) {
		t.Errorf("header of 0x1234-byte record = %x, want %x", got, want)
	}
}

func TestRecordReadRecord(t *testing.T) {
	sh, _ := hex.DecodeString(recordTestServerHelloRecord)
	ch, _ := hex.DecodeString(recordTestClientHelloRecord)
	r := bytes.NewReader(append(append([]byte{}, sh...), ch...))

	tests := []struct {
		name    string
		record  []byte
		version tlsVersion
	}{
		{"RFC 8448 ServerHello", sh, 0x0303},
		{"RFC 8448 ClientHello", ch, 0x0301},
	}
	for _, tt := range tests {
		p, err := readRecord(r)
		if err != nil {
			t.Fatalf("%s: ReadRecord() error = %v", tt.name, err)
		}
		if p.contentType != contentTypeHandshake {
			t.Errorf("%s: Type = %d, want %d", tt.name, p.contentType, contentTypeHandshake)
		}
		if p.version != tt.version {
			t.Errorf("%s: Version = %#04x, want %#04x", tt.name, uint16(p.version), uint16(tt.version))
		}
		if int(p.length) != len(tt.record)-5 {
			t.Errorf("%s: Length = %d, want %d", tt.name, p.length, len(tt.record)-5)
		}
		if !bytes.Equal(p.payload, tt.record[5:]) {
			t.Errorf("%s: Payload =\n%x\nwant\n%x", tt.name, p.payload, tt.record[5:])
		}
	}

	if _, err := readRecord(r); err != io.EOF {
		t.Errorf("ReadRecord() at end of stream error = %v, want io.EOF", err)
	}
}

func TestRecordReadRecordMaxPayload(t *testing.T) {
	n := maxPayloadLen
	data := append([]byte{0x17, 0x03, 0x03, byte(n >> 8), byte(n)}, make([]byte, n)...)
	p, err := readRecord(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadRecord() with %d-byte payload error = %v", maxPayloadLen, err)
	}
	if len(p.payload) != maxPayloadLen {
		t.Errorf("len(Payload) = %d, want %d", len(p.payload), maxPayloadLen)
	}
}

func TestRecordReadRecordErrors(t *testing.T) {
	tooLarge := maxPayloadLen + 1
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{"short header", []byte{0x16, 0x03, 0x03}, io.ErrUnexpectedEOF},
		{"short payload", []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02}, io.ErrUnexpectedEOF},
		{"payload too large", append([]byte{0x17, 0x03, 0x03, byte(tooLarge >> 8), byte(tooLarge)}, make([]byte, tooLarge)...), errPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readRecord(bytes.NewReader(tt.data))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ReadRecord() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRecordInnerPlaintextMarshal(t *testing.T) {
	p := &tlsInnerPlaintext{content: []byte{0x14, 0x00, 0x00, 0x00}, contentType: contentTypeHandshake}
	want := []byte{0x14, 0x00, 0x00, 0x00, 0x16}
	if got := p.marshal(); !bytes.Equal(got, want) {
		t.Errorf("Marshal() = %x, want %x", got, want)
	}
}

func TestRecordParseTLSInnerPlaintext(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantContent []byte
		wantType    contentType
	}{
		{"no padding", []byte{0x01, 0x02, 0x17}, []byte{0x01, 0x02}, contentTypeApplicationData},
		{"with padding", []byte{0x01, 0x00, 0x16, 0x00, 0x00, 0x00}, []byte{0x01, 0x00}, contentTypeHandshake},
		{"empty content", []byte{0x15, 0x00}, []byte{}, contentTypeAlert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parseTLSInnerPlaintext(tt.data)
			if err != nil {
				t.Fatalf("ParseTLSInnerPlaintext(%x) error = %v", tt.data, err)
			}
			if !bytes.Equal(p.content, tt.wantContent) {
				t.Errorf("Content = %x, want %x", p.content, tt.wantContent)
			}
			if p.contentType != tt.wantType {
				t.Errorf("Type = %d, want %d", p.contentType, tt.wantType)
			}
		})
	}
}

func TestRecordParseTLSInnerPlaintextErrors(t *testing.T) {
	for _, data := range [][]byte{nil, {0x00}, {0x00, 0x00, 0x00}} {
		if _, err := parseTLSInnerPlaintext(data); !errors.Is(err, errInnerPlaintextNoType) {
			t.Errorf("ParseTLSInnerPlaintext(%x) error = %v, want %v", data, err, errInnerPlaintextNoType)
		}
	}
}

func TestRecordInnerPlaintextRoundTrip(t *testing.T) {
	in := &tlsInnerPlaintext{content: []byte("hello"), contentType: contentTypeApplicationData}
	padded := append(in.marshal(), 0x00, 0x00)
	out, err := parseTLSInnerPlaintext(padded)
	if err != nil {
		t.Fatalf("ParseTLSInnerPlaintext(%x) error = %v", padded, err)
	}
	if !bytes.Equal(out.content, in.content) || out.contentType != in.contentType {
		t.Errorf("round trip = {%x %d}, want {%x %d}", out.content, out.contentType, in.content, in.contentType)
	}
}
