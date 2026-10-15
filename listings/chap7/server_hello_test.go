package tls13

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const serverHelloTestMessage = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

func TestServerHelloUnmarshal(t *testing.T) {
	msg, _ := hex.DecodeString(serverHelloTestMessage)
	sh, err := unmarshalServerHello(msg[4:])
	if err != nil {
		t.Fatalf("UnmarshalServerHello(RFC 8448 ServerHello) error = %v", err)
	}
	wantRandom, _ := hex.DecodeString("a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928")
	if sh.protocolVersion != 0x0303 {
		t.Errorf("ProtocolVersion = %#04x, want 0x0303", uint16(sh.protocolVersion))
	}
	if !bytes.Equal(sh.random[:], wantRandom) {
		t.Errorf("Random = %x, want %x", sh.random, wantRandom)
	}
	if len(sh.legacySessionID) != 0 {
		t.Errorf("LegacySessionID = %x, want empty", sh.legacySessionID)
	}
	if sh.cipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %#04x, want 0x1301", uint16(sh.cipherSuite))
	}
	if sh.compressionMethod != 0 {
		t.Errorf("CompressionMethod = %d, want 0", sh.compressionMethod)
	}
	if len(sh.extensions) != 2 || sh.extensions[0].extensionType != extKeyShare || sh.extensions[1].extensionType != extSupportedVersions {
		t.Errorf("Extensions = %v, want [key_share supported_versions]", sh.extensions)
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
	sh, err := unmarshalServerHello(body)
	if err != nil {
		t.Fatalf("UnmarshalServerHello(%x) error = %v", body, err)
	}
	if !bytes.Equal(sh.legacySessionID, []byte{0xab, 0xcd}) {
		t.Errorf("LegacySessionID = %x, want abcd", sh.legacySessionID)
	}
	if sh.random[0] != 0x00 || sh.random[31] != 0x1f {
		t.Errorf("Random = %x, want 000102...1f", sh.random)
	}
	if sh.cipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %#04x, want 0x1301", uint16(sh.cipherSuite))
	}
}

func TestServerHelloUnmarshalErrors(t *testing.T) {
	msg, _ := hex.DecodeString(serverHelloTestMessage)
	body := msg[4:]
	for n := 0; n < len(body); n++ {
		if _, err := unmarshalServerHello(body[:n]); err == nil {
			t.Errorf("UnmarshalServerHello(first %d of %d bytes) error = nil, want error", n, len(body))
		}
	}
	trailing := append(append([]byte{}, body...), 0x00)
	if _, err := unmarshalServerHello(trailing); err == nil {
		t.Errorf("UnmarshalServerHello(with trailing byte) error = nil, want error")
	}
	badExt, _ := hex.DecodeString(
		"0303" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"00" +
			"1301" +
			"00" +
			"0003" + "002b00")
	if _, err := unmarshalServerHello(badExt); err == nil {
		t.Errorf("UnmarshalServerHello(broken extension) error = nil, want error")
	}
}

func TestServerHelloSelectedVersion(t *testing.T) {
	msg, _ := hex.DecodeString(serverHelloTestMessage)
	sh, err := unmarshalServerHello(msg[4:])
	if err != nil {
		t.Fatalf("UnmarshalServerHello() error = %v", err)
	}
	v, found := sh.selectedVersion()
	if !found || v != 0x0304 {
		t.Errorf("SelectedVersion() = (%#04x, %v), want (0x0304, true)", uint16(v), found)
	}

	none := &serverHello{extensions: []extension{{extensionType: extKeyShare, payload: []byte{0x03, 0x04}}}}
	if v, found := none.selectedVersion(); found {
		t.Errorf("SelectedVersion() without supported_versions = (%#04x, true), want found = false", uint16(v))
	}
}

func TestServerHelloKeyShare(t *testing.T) {
	msg, _ := hex.DecodeString(serverHelloTestMessage)
	sh, err := unmarshalServerHello(msg[4:])
	if err != nil {
		t.Fatalf("UnmarshalServerHello() error = %v", err)
	}
	wantKey, _ := hex.DecodeString("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
	group, key, found := sh.keyShare()
	if !found {
		t.Fatalf("KeyShare() found = false, want true")
	}
	if group != x25519 {
		t.Errorf("group = %#04x, want %#04x", uint16(group), uint16(x25519))
	}
	if !bytes.Equal(key, wantKey) {
		t.Errorf("publicKey = %x, want %x", key, wantKey)
	}

	none := &serverHello{extensions: []extension{{extensionType: extSupportedVersions, payload: []byte{0x03, 0x04}}}}
	if _, _, found := none.keyShare(); found {
		t.Errorf("KeyShare() without key_share found = true, want false")
	}
	broken := &serverHello{extensions: []extension{{extensionType: extKeyShare, payload: []byte{0x00, 0x1d, 0x00, 0x20, 0x01}}}}
	if _, _, found := broken.keyShare(); found {
		t.Errorf("KeyShare() with truncated key found = true, want false")
	}
}
