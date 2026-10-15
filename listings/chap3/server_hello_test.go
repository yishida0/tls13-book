package tls13

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const serverHelloTestMessage = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

func TestServerHelloUnmarshal(t *testing.T) {
	msg, _ := hex.DecodeString(serverHelloTestMessage)
	sh, err := UnmarshalServerHello(msg[4:])
	if err != nil {
		t.Fatalf("UnmarshalServerHello(RFC 8448 ServerHello) error = %v", err)
	}
	wantRandom, _ := hex.DecodeString("a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928")
	if sh.ProtocolVersion != 0x0303 {
		t.Errorf("ProtocolVersion = %#04x, want 0x0303", uint16(sh.ProtocolVersion))
	}
	if !bytes.Equal(sh.Random[:], wantRandom) {
		t.Errorf("Random = %x, want %x", sh.Random, wantRandom)
	}
	if len(sh.LegacySessionID) != 0 {
		t.Errorf("LegacySessionID = %x, want empty", sh.LegacySessionID)
	}
	if sh.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %#04x, want 0x1301", uint16(sh.CipherSuite))
	}
	if sh.CompressionMethod != 0 {
		t.Errorf("CompressionMethod = %d, want 0", sh.CompressionMethod)
	}
	if len(sh.Extensions) != 2 || sh.Extensions[0].Type != extKeyShare || sh.Extensions[1].Type != extSupportedVersions {
		t.Errorf("Extensions = %v, want [key_share supported_versions]", sh.Extensions)
	}
}

func TestServerHelloUnmarshalSessionID(t *testing.T) {
	body, _ := hex.DecodeString(
		"0303" +
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"02abcd" +
			"1301" +
			"00" +
			"0006" + "002b00020304")
	sh, err := UnmarshalServerHello(body)
	if err != nil {
		t.Fatalf("UnmarshalServerHello(%x) error = %v", body, err)
	}
	if !bytes.Equal(sh.LegacySessionID, []byte{0xab, 0xcd}) {
		t.Errorf("LegacySessionID = %x, want abcd", sh.LegacySessionID)
	}
	if sh.Random[0] != 0x00 || sh.Random[31] != 0x1f {
		t.Errorf("Random = %x, want 000102...1f", sh.Random)
	}
	if sh.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %#04x, want 0x1301", uint16(sh.CipherSuite))
	}
}

func TestServerHelloUnmarshalErrors(t *testing.T) {
	msg, _ := hex.DecodeString(serverHelloTestMessage)
	body := msg[4:]
	for n := 0; n < len(body); n++ {
		if _, err := UnmarshalServerHello(body[:n]); err == nil {
			t.Errorf("UnmarshalServerHello(first %d of %d bytes) error = nil, want error", n, len(body))
		}
	}
	trailing := append(append([]byte{}, body...), 0x00)
	if _, err := UnmarshalServerHello(trailing); err == nil {
		t.Errorf("UnmarshalServerHello(with trailing byte) error = nil, want error")
	}
	badExt, _ := hex.DecodeString(
		"0303" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"00" +
			"1301" +
			"00" +
			"0003" + "002b00")
	if _, err := UnmarshalServerHello(badExt); err == nil {
		t.Errorf("UnmarshalServerHello(broken extension) error = nil, want error")
	}
}

func TestServerHelloSelectedVersion(t *testing.T) {
	msg, _ := hex.DecodeString(serverHelloTestMessage)
	sh, err := UnmarshalServerHello(msg[4:])
	if err != nil {
		t.Fatalf("UnmarshalServerHello() error = %v", err)
	}
	v, found := sh.SelectedVersion()
	if !found || v != 0x0304 {
		t.Errorf("SelectedVersion() = (%#04x, %v), want (0x0304, true)", uint16(v), found)
	}

	none := &ServerHello{Extensions: []Extension{{Type: extKeyShare, Payload: []byte{0x03, 0x04}}}}
	if v, found := none.SelectedVersion(); found {
		t.Errorf("SelectedVersion() without supported_versions = (%#04x, true), want found = false", uint16(v))
	}
}

func TestServerHelloKeyShare(t *testing.T) {
	msg, _ := hex.DecodeString(serverHelloTestMessage)
	sh, err := UnmarshalServerHello(msg[4:])
	if err != nil {
		t.Fatalf("UnmarshalServerHello() error = %v", err)
	}
	wantKey, _ := hex.DecodeString("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
	group, key, found := sh.KeyShare()
	if !found {
		t.Fatalf("KeyShare() found = false, want true")
	}
	if group != X25519 {
		t.Errorf("group = %#04x, want %#04x", uint16(group), uint16(X25519))
	}
	if !bytes.Equal(key, wantKey) {
		t.Errorf("publicKey = %x, want %x", key, wantKey)
	}

	none := &ServerHello{Extensions: []Extension{{Type: extSupportedVersions, Payload: []byte{0x03, 0x04}}}}
	if _, _, found := none.KeyShare(); found {
		t.Errorf("KeyShare() without key_share found = true, want false")
	}
	broken := &ServerHello{Extensions: []Extension{{Type: extKeyShare, Payload: []byte{0x00, 0x1d, 0x00, 0x20, 0x01}}}}
	if _, _, found := broken.KeyShare(); found {
		t.Errorf("KeyShare() with truncated key found = true, want false")
	}
}
