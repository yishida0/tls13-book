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
	p := NewTLSPlaintext(ContentTypeHandshake, fragment)
	if p.Type != ContentTypeHandshake {
		t.Errorf("Type = %d, want %d", p.Type, ContentTypeHandshake)
	}
	if p.Version != 0x0303 {
		t.Errorf("Version = %#04x, want 0x0303", uint16(p.Version))
	}
	if p.Length != 3 {
		t.Errorf("Length = %d, want 3", p.Length)
	}
	if !bytes.Equal(p.Payload, fragment) {
		t.Errorf("Payload = %x, want %x", p.Payload, fragment)
	}
}

func TestRecordMarshal(t *testing.T) {
	sh, _ := hex.DecodeString(recordTestServerHelloRecord)
	if got := NewTLSPlaintext(ContentTypeHandshake, sh[5:]).Marshal(); !bytes.Equal(got, sh) {
		t.Errorf("RFC 8448 ServerHello record:\ngot  %x\nwant %x", got, sh)
	}

	ch, _ := hex.DecodeString(recordTestClientHelloRecord)
	p := &TLSPlaintext{
		Type:    ContentTypeHandshake,
		Version: 0x0301,
		Length:  uint16(len(ch) - 5),
		Payload: ch[5:],
	}
	if got := p.Marshal(); !bytes.Equal(got, ch) {
		t.Errorf("RFC 8448 ClientHello record:\ngot  %x\nwant %x", got, ch)
	}

	big := &TLSPlaintext{Type: ContentTypeApplicationData, Version: 0x0303, Length: 0x1234, Payload: make([]byte, 0x1234)}
	if got, want := big.Marshal()[:5], []byte{0x17, 0x03, 0x03, 0x12, 0x34}; !bytes.Equal(got, want) {
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
		version TLSVersion
	}{
		{"RFC 8448 ServerHello", sh, 0x0303},
		{"RFC 8448 ClientHello", ch, 0x0301},
	}
	for _, tt := range tests {
		p, err := ReadRecord(r)
		if err != nil {
			t.Fatalf("%s: ReadRecord() error = %v", tt.name, err)
		}
		if p.Type != ContentTypeHandshake {
			t.Errorf("%s: Type = %d, want %d", tt.name, p.Type, ContentTypeHandshake)
		}
		if p.Version != tt.version {
			t.Errorf("%s: Version = %#04x, want %#04x", tt.name, uint16(p.Version), uint16(tt.version))
		}
		if int(p.Length) != len(tt.record)-5 {
			t.Errorf("%s: Length = %d, want %d", tt.name, p.Length, len(tt.record)-5)
		}
		if !bytes.Equal(p.Payload, tt.record[5:]) {
			t.Errorf("%s: Payload =\n%x\nwant\n%x", tt.name, p.Payload, tt.record[5:])
		}
	}

	if _, err := ReadRecord(r); err != io.EOF {
		t.Errorf("ReadRecord() at end of stream error = %v, want io.EOF", err)
	}
}

func TestRecordReadRecordMaxPayload(t *testing.T) {
	n := maxPayloadLen
	data := append([]byte{0x17, 0x03, 0x03, byte(n >> 8), byte(n)}, make([]byte, n)...)
	p, err := ReadRecord(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadRecord() with %d-byte payload error = %v", maxPayloadLen, err)
	}
	if len(p.Payload) != maxPayloadLen {
		t.Errorf("len(Payload) = %d, want %d", len(p.Payload), maxPayloadLen)
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
			_, err := ReadRecord(bytes.NewReader(tt.data))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ReadRecord() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
