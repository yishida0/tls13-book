package tls13

import "testing"

func TestCommonContentType(t *testing.T) {
	tests := []struct {
		name string
		got  ContentType
		want uint8
	}{
		{"change_cipher_spec", ContentTypeChangeCipherSpec, 20},
		{"alert", ContentTypeAlert, 21},
		{"handshake", ContentTypeHandshake, 22},
		{"application_data", ContentTypeApplicationData, 23},
	}
	for _, tt := range tests {
		if uint8(tt.got) != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestCommonTLSVersion(t *testing.T) {
	if TLS_VERSION_1_2 != 0x0303 {
		t.Errorf("TLS_VERSION_1_2 = %#04x, want 0x0303", uint16(TLS_VERSION_1_2))
	}
	if TLS_VERSION_1_3 != 0x0304 {
		t.Errorf("TLS_VERSION_1_3 = %#04x, want 0x0304", uint16(TLS_VERSION_1_3))
	}
}

func TestCommonHandshakeType(t *testing.T) {
	tests := []struct {
		name string
		got  HandshakeType
		want uint8
	}{
		{"client_hello", TypeClientHello, 1},
		{"server_hello", TypeServerHello, 2},
		{"encrypted_extensions", TypeEncryptedExtensions, 8},
		{"certificate", TypeCertificate, 11},
		{"certificate_verify", TypeCertificateVerify, 15},
		{"finished", TypeFinished, 20},
	}
	for _, tt := range tests {
		if uint8(tt.got) != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestCommonMaxPayloadLen(t *testing.T) {
	if maxPayloadLen != 16640 {
		t.Errorf("MaxPayloadLen = %d, want 16640 (2^14 + 256)", maxPayloadLen)
	}
}
