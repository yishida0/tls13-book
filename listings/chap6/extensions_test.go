package tls13

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const extensionsTestClientPublicKey = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"

func TestExtensionsMarshal(t *testing.T) {
	tests := []struct {
		name string
		ext  Extension
		want string
	}{
		{"RFC 8448 renegotiation_info", Extension{Type: 0xff01, Payload: []byte{0x00}}, "ff01000100"},
		{"RFC 8448 session_ticket empty", Extension{Type: 0x0023}, "00230000"},
		{"RFC 8448 supported_versions", Extension{Type: extSupportedVersions, Payload: []byte{0x02, 0x03, 0x04}}, "002b0003020304"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, _ := hex.DecodeString(tt.want)
			if got := tt.ext.Marshal(); !bytes.Equal(got, want) {
				t.Errorf("Marshal() = %x, want %x", got, want)
			}
		})
	}
}

func TestExtensionsBuilders(t *testing.T) {
	pub, _ := hex.DecodeString(extensionsTestClientPublicKey)
	tests := []struct {
		name     string
		ext      Extension
		wantType extensionType
		want     string
	}{
		{"RFC 8448 supported_versions", SupportedVersionsExtension(), extSupportedVersions, "002b0003020304"},
		{"RFC 8448 server_name", ServerNameExtension("server"), extServerName, "0000000b0009000006736572766572"},
		{"RFC 8448 key_share", KeyShareExtension(pub), extKeyShare, "003300260024001d0020" + extensionsTestClientPublicKey},
		{"supported_groups", SupportedGroupsExtension(), extSupportedGroups, "000a00040002001d"},
		{"signature_algorithms", SignatureAlgorithmsExtension(), extSignatureAlgorithms, "000d000e000c040305030804080508060401"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ext.Type != tt.wantType {
				t.Errorf("Type = %d, want %d", tt.ext.Type, tt.wantType)
			}
			want, _ := hex.DecodeString(tt.want)
			if got := tt.ext.Marshal(); !bytes.Equal(got, want) {
				t.Errorf("Marshal() =\n%x\nwant\n%x", got, want)
			}
		})
	}
}

func TestExtensionsUnmarshal(t *testing.T) {
	block, _ := hex.DecodeString("0000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
	want := []struct {
		typ     extensionType
		payload string
	}{
		{0x0000, "0009000006736572766572"},
		{0xff01, "00"},
		{0x000a, "0012001d00170018001901000101010201030104"},
		{0x0023, ""},
		{0x0033, "0024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"},
		{0x002b, "020304"},
		{0x000d, "001e040305030603020308040805080604010501060102010402050206020202"},
		{0x002d, "0101"},
		{0x001c, "4001"},
	}

	exts, ok := UnmarshalExtensions(block)
	if !ok {
		t.Fatalf("UnmarshalExtensions(RFC 8448 ClientHello extensions) ok = false")
	}
	if len(exts) != len(want) {
		t.Fatalf("len(exts) = %d, want %d", len(exts), len(want))
	}
	var remarshaled []byte
	for i, w := range want {
		wantPayload, _ := hex.DecodeString(w.payload)
		if exts[i].Type != w.typ {
			t.Errorf("exts[%d].Type = %#04x, want %#04x", i, uint16(exts[i].Type), uint16(w.typ))
		}
		if !bytes.Equal(exts[i].Payload, wantPayload) {
			t.Errorf("exts[%d].Payload = %x, want %x", i, exts[i].Payload, wantPayload)
		}
		remarshaled = append(remarshaled, exts[i].Marshal()...)
	}
	if !bytes.Equal(remarshaled, block) {
		t.Errorf("re-marshaled extensions =\n%x\nwant\n%x", remarshaled, block)
	}
}

func TestExtensionsUnmarshalCopiesPayload(t *testing.T) {
	data := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	exts, ok := UnmarshalExtensions(data)
	if !ok || len(exts) != 1 {
		t.Fatalf("UnmarshalExtensions(%x) = (%v, %v)", data, exts, ok)
	}
	data[4] = 0xff
	if !bytes.Equal(exts[0].Payload, []byte{0x03, 0x04}) {
		t.Errorf("Payload changed with input buffer: %x, want 0304", exts[0].Payload)
	}
}

func TestExtensionsUnmarshalEmpty(t *testing.T) {
	exts, ok := UnmarshalExtensions(nil)
	if !ok || len(exts) != 0 {
		t.Errorf("UnmarshalExtensions(empty) = (%v, %v), want ([], true)", exts, ok)
	}
}

func TestExtensionsUnmarshalErrors(t *testing.T) {
	for _, s := range []string{
		"00",
		"002b",
		"002b00",
		"002b000302",
		"002b0003020304ff",
	} {
		data, _ := hex.DecodeString(s)
		if exts, ok := UnmarshalExtensions(data); ok {
			t.Errorf("UnmarshalExtensions(%s) = (%v, true), want ok = false", s, exts)
		}
	}
}
