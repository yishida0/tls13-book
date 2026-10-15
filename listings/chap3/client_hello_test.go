package tls13

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestClientHelloNew(t *testing.T) {
	var random [32]byte
	for i := range random {
		random[i] = byte(i)
	}
	exts := []Extension{{Type: extSupportedVersions, Payload: []byte{0x02, 0x03, 0x04}}}
	ch := NewClientHello(random, exts)

	if ch.ProtocolVersion != 0x0303 {
		t.Errorf("ProtocolVersion = %#04x, want 0x0303", uint16(ch.ProtocolVersion))
	}
	if ch.Random != random {
		t.Errorf("Random = %x, want %x", ch.Random, random)
	}
	if len(ch.LegacySessionID) != 0 {
		t.Errorf("LegacySessionID = %x, want empty", ch.LegacySessionID)
	}
	if len(ch.CipherSuites) != 1 || ch.CipherSuites[0] != 0x1301 {
		t.Errorf("CipherSuites = %v, want [0x1301]", ch.CipherSuites)
	}
	if !bytes.Equal(ch.LegacyCompressionMethods, []byte{0x00}) {
		t.Errorf("LegacyCompressionMethods = %x, want 00", ch.LegacyCompressionMethods)
	}
	if len(ch.Extensions) != 1 || ch.Extensions[0].Type != extSupportedVersions {
		t.Errorf("Extensions = %v, want %v", ch.Extensions, exts)
	}
}

func TestClientHelloMarshal(t *testing.T) {
	var random [32]byte
	for i := range random {
		random[i] = byte(i)
	}
	ch := NewClientHello(random, []Extension{{Type: extSupportedVersions, Payload: []byte{0x02, 0x03, 0x04}}})
	want, _ := hex.DecodeString(
		"0303" +
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"00" +
			"00021301" +
			"0100" +
			"0007" + "002b0003020304")
	if got := ch.Marshal(); !bytes.Equal(got, want) {
		t.Errorf("Marshal() =\n%x\nwant\n%x", got, want)
	}
}

func TestClientHelloMarshalRFC8448(t *testing.T) {
	random, _ := hex.DecodeString("cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7")
	rawExts := []struct {
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
	var exts []Extension
	for _, e := range rawExts {
		payload, _ := hex.DecodeString(e.payload)
		exts = append(exts, Extension{Type: e.typ, Payload: payload})
	}
	ch := &ClientHello{
		ProtocolVersion:          TLS_VERSION_1_2,
		LegacySessionID:          nil,
		CipherSuites:             []CipherSuite{0x1301, 0x1303, 0x1302},
		LegacyCompressionMethods: []byte{0x00},
		Extensions:               exts,
	}
	copy(ch.Random[:], random)

	msg, _ := hex.DecodeString("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
	want := msg[4:]
	if got := ch.Marshal(); !bytes.Equal(got, want) {
		t.Errorf("Marshal() =\n%x\nwant (RFC 8448 ClientHello body)\n%x", got, want)
	}
}

func TestClientHelloMarshalSessionID(t *testing.T) {
	ch := &ClientHello{
		ProtocolVersion:          TLS_VERSION_1_2,
		LegacySessionID:          []byte{0xaa, 0xbb, 0xcc},
		CipherSuites:             []CipherSuite{0x1301},
		LegacyCompressionMethods: []byte{0x00},
	}
	want, _ := hex.DecodeString(
		"0303" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"03aabbcc" +
			"00021301" +
			"0100" +
			"0000")
	if got := ch.Marshal(); !bytes.Equal(got, want) {
		t.Errorf("Marshal() =\n%x\nwant\n%x", got, want)
	}
}
