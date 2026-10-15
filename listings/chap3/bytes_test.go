package tls13

import (
	"bytes"
	"testing"
)

func TestBytesAppendUint16(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		v    uint16
		want []byte
	}{
		{"nil", nil, 0x0304, []byte{0x03, 0x04}},
		{"append", []byte{0xaa}, 0x1301, []byte{0xaa, 0x13, 0x01}},
		{"high byte only", nil, 0xff00, []byte{0xff, 0x00}},
	}
	for _, tt := range tests {
		if got := appendUint16(tt.b, tt.v); !bytes.Equal(got, tt.want) {
			t.Errorf("%s: appendUint16(%x, %#04x) = %x, want %x", tt.name, tt.b, tt.v, got, tt.want)
		}
	}
}

func TestBytesWithUint8Length(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want []byte
	}{
		{"empty", nil, []byte{0x00}},
		{"two bytes", []byte{0x03, 0x04}, []byte{0x02, 0x03, 0x04}},
	}
	for _, tt := range tests {
		if got := withUint8Length(tt.body); !bytes.Equal(got, tt.want) {
			t.Errorf("%s: withUint8Length(%x) = %x, want %x", tt.name, tt.body, got, tt.want)
		}
	}
}

func TestBytesWithUint16Length(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want []byte
	}{
		{"empty", nil, []byte{0x00, 0x00}},
		{"two bytes", []byte{0x13, 0x01}, []byte{0x00, 0x02, 0x13, 0x01}},
	}
	for _, tt := range tests {
		if got := withUint16Length(tt.body); !bytes.Equal(got, tt.want) {
			t.Errorf("%s: withUint16Length(%x) = %x, want %x", tt.name, tt.body, got, tt.want)
		}
	}

	long := bytes.Repeat([]byte{0xab}, 0x0123)
	got := withUint16Length(long)
	if len(got) != 2+0x0123 || got[0] != 0x01 || got[1] != 0x23 || !bytes.Equal(got[2:], long) {
		t.Errorf("withUint16Length(0x0123 bytes) prefix = %x, want 0123", got[:2])
	}
}

func TestBytesReadUint8(t *testing.T) {
	v, rest, ok := readUint8([]byte{0x16, 0x03})
	if !ok || v != 0x16 || !bytes.Equal(rest, []byte{0x03}) {
		t.Errorf("readUint8(1603) = (%#02x, %x, %v), want (0x16, 03, true)", v, rest, ok)
	}
	if _, _, ok := readUint8(nil); ok {
		t.Errorf("readUint8(empty) ok = true, want false")
	}
}

func TestBytesReadUint16(t *testing.T) {
	v, rest, ok := readUint16([]byte{0x13, 0x01, 0xff})
	if !ok || v != 0x1301 || !bytes.Equal(rest, []byte{0xff}) {
		t.Errorf("readUint16(1301ff) = (%#04x, %x, %v), want (0x1301, ff, true)", v, rest, ok)
	}
	if _, _, ok := readUint16([]byte{0x13}); ok {
		t.Errorf("readUint16(13) ok = true, want false")
	}
}

func TestBytesReadBytes(t *testing.T) {
	v, rest, ok := readBytes([]byte{0x01, 0x02, 0x03}, 2)
	if !ok || !bytes.Equal(v, []byte{0x01, 0x02}) || !bytes.Equal(rest, []byte{0x03}) {
		t.Errorf("readBytes(010203, 2) = (%x, %x, %v), want (0102, 03, true)", v, rest, ok)
	}
	v, rest, ok = readBytes([]byte{0x01, 0x02}, 2)
	if !ok || !bytes.Equal(v, []byte{0x01, 0x02}) || len(rest) != 0 {
		t.Errorf("readBytes(0102, 2) = (%x, %x, %v), want (0102, , true)", v, rest, ok)
	}
	if _, _, ok := readBytes([]byte{0x01}, 2); ok {
		t.Errorf("readBytes(01, 2) ok = true, want false")
	}
}

func TestBytesReadPrefixed(t *testing.T) {
	tests := []struct {
		name      string
		read      func([]byte) ([]byte, []byte, bool)
		in        []byte
		wantValue []byte
		wantRest  []byte
		wantOK    bool
	}{
		{"uint8", readUint8Prefixed, []byte{0x02, 0xaa, 0xbb, 0xcc}, []byte{0xaa, 0xbb}, []byte{0xcc}, true},
		{"uint8 empty value", readUint8Prefixed, []byte{0x00, 0xcc}, []byte{}, []byte{0xcc}, true},
		{"uint8 no length", readUint8Prefixed, nil, nil, nil, false},
		{"uint8 short value", readUint8Prefixed, []byte{0x03, 0xaa, 0xbb}, nil, nil, false},
		{"uint16", readUint16Prefixed, []byte{0x00, 0x02, 0xaa, 0xbb, 0xcc}, []byte{0xaa, 0xbb}, []byte{0xcc}, true},
		{"uint16 uses high byte", readUint16Prefixed, []byte{0x01, 0x00, 0xaa}, nil, nil, false},
		{"uint16 short length", readUint16Prefixed, []byte{0x00}, nil, nil, false},
		{"uint24", readUint24Prefixed, []byte{0x00, 0x00, 0x02, 0xaa, 0xbb, 0xcc}, []byte{0xaa, 0xbb}, []byte{0xcc}, true},
		{"uint24 uses middle byte", readUint24Prefixed, []byte{0x00, 0x01, 0x00, 0xaa}, nil, nil, false},
		{"uint24 uses high byte", readUint24Prefixed, []byte{0x01, 0x00, 0x00, 0xaa}, nil, nil, false},
		{"uint24 short length", readUint24Prefixed, []byte{0x00, 0x00}, nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, rest, ok := tt.read(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if !bytes.Equal(v, tt.wantValue) || !bytes.Equal(rest, tt.wantRest) {
				t.Errorf("read(%x) = (%x, %x), want (%x, %x)", tt.in, v, rest, tt.wantValue, tt.wantRest)
			}
		})
	}

	long := append([]byte{0x00, 0x01, 0x00}, bytes.Repeat([]byte{0xab}, 0x0100)...)
	if v, _, ok := readUint24Prefixed(long); !ok || len(v) != 0x0100 {
		t.Errorf("readUint24Prefixed(len 0x000100) = (len %d, %v), want (256, true)", len(v), ok)
	}
	long16 := append([]byte{0x01, 0x00}, bytes.Repeat([]byte{0xab}, 0x0100)...)
	if v, _, ok := readUint16Prefixed(long16); !ok || len(v) != 0x0100 {
		t.Errorf("readUint16Prefixed(len 0x0100) = (len %d, %v), want (256, true)", len(v), ok)
	}
}
