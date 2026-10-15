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

func TestCommonCipherSuite(t *testing.T) {
	if TLS_AES_128_GCM_SHA256 != 0x1301 {
		t.Errorf("TLS_AES_128_GCM_SHA256 = %#04x, want 0x1301", uint16(TLS_AES_128_GCM_SHA256))
	}
}

func TestCommonExtensionType(t *testing.T) {
	tests := []struct {
		name string
		got  extensionType
		want uint16
	}{
		{"server_name", extServerName, 0},
		{"supported_groups", extSupportedGroups, 10},
		{"signature_algorithms", extSignatureAlgorithms, 13},
		{"supported_versions", extSupportedVersions, 43},
		{"key_share", extKeyShare, 51},
	}
	for _, tt := range tests {
		if uint16(tt.got) != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestCommonNamedGroup(t *testing.T) {
	if X25519 != 0x001d {
		t.Errorf("X25519 = %#04x, want 0x001d", uint16(X25519))
	}
}

func TestCommonSignatureScheme(t *testing.T) {
	tests := []struct {
		name string
		got  SignatureScheme
		want uint16
	}{
		{"rsa_pkcs1_sha256", RSA_PKCS1_SHA256, 0x0401},
		{"ecdsa_secp256r1_sha256", ECDSA_SECP256R1_SHA256, 0x0403},
		{"ecdsa_secp384r1_sha384", ECDSA_SECP384R1_SHA384, 0x0503},
		{"rsa_pss_rsae_sha256", RSA_PSS_RSAE_SHA256, 0x0804},
		{"rsa_pss_rsae_sha384", RSA_PSS_RSAE_SHA384, 0x0805},
		{"rsa_pss_rsae_sha512", RSA_PSS_RSAE_SHA512, 0x0806},
	}
	for _, tt := range tests {
		if uint16(tt.got) != tt.want {
			t.Errorf("%s = %#04x, want %#04x", tt.name, uint16(tt.got), tt.want)
		}
	}
}
