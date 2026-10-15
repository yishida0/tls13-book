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
	exts := []extension{{extensionType: extSupportedVersions, payload: []byte{0x02, 0x03, 0x04}}}
	ch := newClientHello(random, exts)

	if ch.protocolVersion != 0x0303 {
		t.Errorf("ProtocolVersion = %#04x, want 0x0303", uint16(ch.protocolVersion))
	}
	if ch.random != random {
		t.Errorf("Random = %x, want %x", ch.random, random)
	}
	if len(ch.legacySessionID) != 0 {
		t.Errorf("LegacySessionID = %x, want empty", ch.legacySessionID)
	}
	if len(ch.cipherSuites) != 1 || ch.cipherSuites[0] != 0x1301 {
		t.Errorf("CipherSuites = %v, want [0x1301]", ch.cipherSuites)
	}
	if !bytes.Equal(ch.legacyCompressionMethods, []byte{0x00}) {
		t.Errorf("LegacyCompressionMethods = %x, want 00", ch.legacyCompressionMethods)
	}
	if len(ch.extensions) != 1 || ch.extensions[0].extensionType != extSupportedVersions {
		t.Errorf("Extensions = %v, want %v", ch.extensions, exts)
	}
}

func TestClientHelloMarshal(t *testing.T) {
	var random [32]byte
	for i := range random {
		random[i] = byte(i)
	}
	ch := newClientHello(random, []extension{{extensionType: extSupportedVersions, payload: []byte{0x02, 0x03, 0x04}}})
	want, _ := hex.DecodeString(
		"0303" +
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"00" +
			"00021301" +
			"0100" +
			"0007" + "002b0003020304")
	if got := ch.marshal(); !bytes.Equal(got, want) {
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
	var exts []extension
	for _, e := range rawExts {
		payload, _ := hex.DecodeString(e.payload)
		exts = append(exts, extension{extensionType: e.typ, payload: payload})
	}
	ch := &clientHello{
		protocolVersion:          tls_version_1_2,
		legacySessionID:          nil,
		cipherSuites:             []cipherSuite{0x1301, 0x1303, 0x1302},
		legacyCompressionMethods: []byte{0x00},
		extensions:               exts,
	}
	copy(ch.random[:], random)

	msg, _ := hex.DecodeString("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
	want := msg[4:]
	if got := ch.marshal(); !bytes.Equal(got, want) {
		t.Errorf("Marshal() =\n%x\nwant (RFC 8448 ClientHello body)\n%x", got, want)
	}
}

func TestClientHelloMarshalSessionID(t *testing.T) {
	ch := &clientHello{
		protocolVersion:          tls_version_1_2,
		legacySessionID:          []byte{0xaa, 0xbb, 0xcc},
		cipherSuites:             []cipherSuite{0x1301},
		legacyCompressionMethods: []byte{0x00},
	}
	want, _ := hex.DecodeString(
		"0303" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"03aabbcc" +
			"00021301" +
			"0100" +
			"0000")
	if got := ch.marshal(); !bytes.Equal(got, want) {
		t.Errorf("Marshal() =\n%x\nwant\n%x", got, want)
	}
}
