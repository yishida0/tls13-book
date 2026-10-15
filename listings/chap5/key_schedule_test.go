package tls13

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

var (
	keyScheduleTestClientHello = keyScheduleTestHex(
		"010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef" +
			"6283024dece7000006130113031302010000910000000b000900000673657276" +
			"6572ff01000100000a00140012001d0017001800190100010101020103010400" +
			"230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e" +
			"51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603" +
			"020308040805080604010501060102010402050206020202002d00020101001c" +
			"00024001")
	keyScheduleTestServerHello = keyScheduleTestHex(
		"020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155" +
			"772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb" +
			"f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304")
	keyScheduleTestSharedSecret = keyScheduleTestHex(
		"8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
)

func keyScheduleTestHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func keyScheduleTestExpect(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if !bytes.Equal(got, keyScheduleTestHex(want)) {
		t.Errorf("%s\n got: %x\nwant: %s", name, got, want)
	}
}

func TestKeyScheduleHkdfLabel(t *testing.T) {
	emptyHash := sha256.Sum256(nil)
	label := newHkdfLabel("derived", emptyHash[:], 32)
	keyScheduleTestExpect(t, "HkdfLabel", label.marshal(),
		"00200d746c733133206465726976656420e3b0c44298fc1c149afbf4c8996fb9"+
			"2427ae41e4649b934ca495991b7852b855")
}

func TestKeyScheduleTranscript(t *testing.T) {
	tr := newTranscript()
	tr.write(keyScheduleTestClientHello)
	tr.write(keyScheduleTestServerHello)
	keyScheduleTestExpect(t, "Transcript Hash", tr.sum(),
		"860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
}

func TestKeySchedule(t *testing.T) {
	keyScheduleTestExpect(t, "Early Secret", deriveEarlySecret(),
		"33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")

	handshakeSecret := deriveHandshakeSecret(keyScheduleTestSharedSecret)
	keyScheduleTestExpect(t, "Handshake Secret", handshakeSecret,
		"1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")

	tr := newTranscript()
	tr.write(keyScheduleTestClientHello)
	tr.write(keyScheduleTestServerHello)
	keyScheduleTestExpect(t, "client_handshake_traffic_secret", deriveSecret(handshakeSecret, "c hs traffic", tr.sum()),
		"b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
	keyScheduleTestExpect(t, "server_handshake_traffic_secret", deriveSecret(handshakeSecret, "s hs traffic", tr.sum()),
		"b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")

	mainSecret := deriveMainSecret(handshakeSecret)
	keyScheduleTestExpect(t, "Main Secret", mainSecret,
		"18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")

	applicationTranscriptHash := keyScheduleTestHex(
		"9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
	keyScheduleTestExpect(t, "client_application_traffic_secret_0", deriveSecret(mainSecret, "c ap traffic", applicationTranscriptHash),
		"9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
	keyScheduleTestExpect(t, "server_application_traffic_secret_0", deriveSecret(mainSecret, "s ap traffic", applicationTranscriptHash),
		"a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
}

func TestKeyScheduleTrafficKeys(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantKey string
		wantIV  string
	}{
		{
			name:    "server handshake",
			secret:  "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
			wantKey: "3fce516009c21727d0f2e4e86ee403bc",
			wantIV:  "5d313eb2671276ee13000b30",
		},
		{
			name:    "client handshake",
			secret:  "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
			wantKey: "dbfaa693d1762c5b666af5d950258d01",
			wantIV:  "5bd3c71b836e0b76bb73265f",
		},
		{
			name:    "server application",
			secret:  "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
			wantKey: "9f02283b6c9c07efc26bb9f2ac92e356",
			wantIV:  "cf782b88dd83549aadf1e984",
		},
		{
			name:    "client application",
			secret:  "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
			wantKey: "17422dda596ed5d9acd890e3c63f5051",
			wantIV:  "5b78923dee08579033e523d9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, iv := trafficKeys(keyScheduleTestHex(tt.secret))
			keyScheduleTestExpect(t, "key", key, tt.wantKey)
			keyScheduleTestExpect(t, "iv", iv, tt.wantIV)
		})
	}
}
