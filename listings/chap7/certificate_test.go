package tls13

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

var (
	certificateTestClientHello = certificateTestHex(
		"010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef" +
			"6283024dece7000006130113031302010000910000000b000900000673657276" +
			"6572ff01000100000a00140012001d0017001800190100010101020103010400" +
			"230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e" +
			"51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603" +
			"020308040805080604010501060102010402050206020202002d00020101001c" +
			"00024001")
	certificateTestServerHello = certificateTestHex(
		"020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155" +
			"772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb" +
			"f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304")
	certificateTestEncryptedExtensions = certificateTestHex(
		"080000240022000a00140012001d00170018001901000101010201030104001c" +
			"0002400100000000")
	certificateTestCertificate = certificateTestHex(
		"0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a" +
			"864886f70d01010b0500300e310c300a06035504031303727361301e170d3136" +
			"303733303031323335395a170d3236303733303031323335395a300e310c300a" +
			"0603550403130372736130819f300d06092a864886f70d010101050003818d00" +
			"30818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826" +
			"d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312" +
			"0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda4308467480" +
			"30530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a" +
			"8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355" +
			"1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5" +
			"b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a5" +
			"8c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102" +
			"702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0" +
			"a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000")
	certificateTestCertificateVerify = certificateTestHex(
		"0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145a" +
			"b3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248ee" +
			"aaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c" +
			"9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea2" +
			"0d53dfacd42f74f3")
)

func certificateTestHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func certificateTestTranscriptHash() []byte {
	tr := newTranscript()
	tr.write(certificateTestClientHello)
	tr.write(certificateTestServerHello)
	tr.write(certificateTestEncryptedExtensions)
	tr.write(certificateTestCertificate)
	return tr.sum()
}

func certificateTestParseServerCert(t *testing.T) *x509.Certificate {
	t.Helper()
	c, err := unmarshalCertificate(certificateTestCertificate[4:])
	if err != nil {
		t.Fatalf("UnmarshalCertificate: %v", err)
	}
	if len(c.certificateList) != 1 {
		t.Fatalf("len(CertificateList) = %d, want 1", len(c.certificateList))
	}
	cert, err := x509.ParseCertificate(c.certificateList[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return cert
}

func TestCertificateUnmarshal(t *testing.T) {
	c, err := unmarshalCertificate(certificateTestCertificate[4:])
	if err != nil {
		t.Fatalf("UnmarshalCertificate: %v", err)
	}
	if len(c.certificateList) != 1 {
		t.Fatalf("len(CertificateList) = %d, want 1", len(c.certificateList))
	}
	want := certificateTestCertificate[11 : len(certificateTestCertificate)-2]
	if !bytes.Equal(c.certificateList[0], want) {
		t.Errorf("CertificateList[0]\n got: %x\nwant: %x", c.certificateList[0], want)
	}

	cert := certificateTestParseServerCert(t)
	if cert.Subject.CommonName != "rsa" {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, "rsa")
	}
}

func TestCertificateUnmarshalChain(t *testing.T) {
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	entry := append([]byte{0x00, 0x00, byte(len(der))}, der...)
	entry = append(entry, 0x00, 0x00)
	extEntry := append([]byte{0x00, 0x00, byte(len(der))}, der...)
	extEntry = append(extEntry, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00)
	list := append(append([]byte{}, entry...), extEntry...)
	body := append([]byte{0x00, 0x00, 0x00, byte(len(list))}, list...)

	c, err := unmarshalCertificate(body)
	if err != nil {
		t.Fatalf("UnmarshalCertificate: %v", err)
	}
	if len(c.certificateList) != 2 {
		t.Fatalf("len(CertificateList) = %d, want 2", len(c.certificateList))
	}
	for i, got := range c.certificateList {
		if !bytes.Equal(got, der) {
			t.Errorf("CertificateList[%d]\n got: %x\nwant: %x", i, got, der)
		}
	}
}

func TestCertificateUnmarshalMalformed(t *testing.T) {
	body := certificateTestCertificate[4:]
	tests := []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"truncated", body[:len(body)-1]},
		{"trailing data", append(append([]byte{}, body...), 0x00)},
	}
	for _, tt := range tests {
		if _, err := unmarshalCertificate(tt.body); err == nil {
			t.Errorf("%s: want error, got nil", tt.name)
		}
	}
}

func TestCertificateVerifyUnmarshal(t *testing.T) {
	cv, err := unmarshalCertificateVerify(certificateTestCertificateVerify[4:])
	if err != nil {
		t.Fatalf("UnmarshalCertificateVerify: %v", err)
	}
	if cv.algorithm != rsa_pss_rsae_sha256 {
		t.Errorf("Algorithm = %#04x, want %#04x", uint16(cv.algorithm), uint16(rsa_pss_rsae_sha256))
	}
	want := certificateTestCertificateVerify[8:]
	if !bytes.Equal(cv.signature, want) {
		t.Errorf("Signature\n got: %x\nwant: %x", cv.signature, want)
	}

	body := certificateTestCertificateVerify[4:]
	for _, bad := range [][]byte{nil, body[:3], body[:len(body)-1], append(append([]byte{}, body...), 0x00)} {
		if _, err := unmarshalCertificateVerify(bad); err == nil {
			t.Errorf("UnmarshalCertificateVerify(%d bytes): want error, got nil", len(bad))
		}
	}
}

func TestCertificateVerifyVerify(t *testing.T) {
	cert := certificateTestParseServerCert(t)
	cv, err := unmarshalCertificateVerify(certificateTestCertificateVerify[4:])
	if err != nil {
		t.Fatalf("UnmarshalCertificateVerify: %v", err)
	}
	transcriptHash := certificateTestTranscriptHash()

	if err := cv.verify(cert, transcriptHash); err != nil {
		t.Errorf("Verify with the RFC 8448 transcript: %v", err)
	}

	wrongHash := append([]byte{}, transcriptHash...)
	wrongHash[0] ^= 0x01
	if err := cv.verify(cert, wrongHash); err == nil {
		t.Error("Verify with a modified transcript hash: want error, got nil")
	}

	badSig := &certificateVerify{algorithm: cv.algorithm, signature: append([]byte{}, cv.signature...)}
	badSig.signature[10] ^= 0x01
	if err := badSig.verify(cert, transcriptHash); err == nil {
		t.Error("Verify with a modified signature: want error, got nil")
	}

	ecdsaScheme := &certificateVerify{algorithm: ecdsa_secp256r1_sha256, signature: cv.signature}
	if err := ecdsaScheme.verify(cert, transcriptHash); err == nil {
		t.Error("Verify ECDSA scheme with an RSA certificate: want error, got nil")
	}

	unknown := &certificateVerify{algorithm: signatureScheme(0x0201), signature: cv.signature}
	if err := unknown.verify(cert, transcriptHash); err == nil {
		t.Error("Verify with unsupported scheme 0x0201: want error, got nil")
	}
}
