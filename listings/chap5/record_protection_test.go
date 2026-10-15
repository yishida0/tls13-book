package tls13

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	recordProtectionTestServerHandshakeSecret = recordProtectionTestHex(
		"b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	recordProtectionTestClientHandshakeSecret = recordProtectionTestHex(
		"b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
	recordProtectionTestServerApplicationSecret = recordProtectionTestHex(
		"a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
	recordProtectionTestClientApplicationSecret = recordProtectionTestHex(
		"9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
)

func recordProtectionTestHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func recordProtectionTestExpect(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s\n got: %x\nwant: %x", name, got, want)
	}
}

func TestRecordProtectionNonce(t *testing.T) {
	p := newRecordProtection(recordProtectionTestServerHandshakeSecret)
	iv := recordProtectionTestHex(
		"5d313eb2671276ee13000b30")

	recordProtectionTestExpect(t, "nonce for seq 0", p.nextNonce(), iv)

	want := append([]byte(nil), iv...)
	want[11] ^= 0x01
	recordProtectionTestExpect(t, "nonce for seq 1", p.nextNonce(), want)

	p.seq = 0x0102030405060708
	want = append([]byte(nil), iv...)
	for i, b := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
		want[4+i] ^= b
	}
	recordProtectionTestExpect(t, "nonce for seq 0x0102030405060708", p.nextNonce(), want)

	if p.seq != 0x0102030405060709 {
		t.Errorf("seq = %#x, want 0x0102030405060709", p.seq)
	}
	recordProtectionTestExpect(t, "iv must not change", p.iv, iv)
}

func TestRecordProtectionAdditionalData(t *testing.T) {
	record := recordProtectionTestHex(
		"17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35e" +
			"df7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78" +
			"b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b" +
			"d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9" +
			"d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2e" +
			"d65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092" +
			"8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead68694" +
			"5ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b368" +
			"4596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f" +
			"4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26" +
			"f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b65962224531" +
			"7b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e" +
			"1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da" +
			"8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d4" +
			"61e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe" +
			"5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb" +
			"992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c859" +
			"77b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038" +
			"ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b84" +
			"5e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5" +
			"d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e" +
			"750edc53370d2b")
	recordProtectionTestExpect(t, "additionalData", additionalData(ContentTypeApplicationData, TLS_VERSION_1_2, len(record)-5), record[:5])
}

func TestRecordProtectionDecryptServerHandshake(t *testing.T) {
	record := recordProtectionTestHex(
		"17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35e" +
			"df7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78" +
			"b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b" +
			"d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9" +
			"d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2e" +
			"d65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092" +
			"8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead68694" +
			"5ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b368" +
			"4596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f" +
			"4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26" +
			"f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b65962224531" +
			"7b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e" +
			"1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da" +
			"8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d4" +
			"61e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe" +
			"5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb" +
			"992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c859" +
			"77b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038" +
			"ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b84" +
			"5e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5" +
			"d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e" +
			"750edc53370d2b")
	want := recordProtectionTestHex(
		"080000240022000a00140012001d00170018001901000101010201030104001c" +
			"00024001000000000b0001b9000001b50001b0308201ac30820115a003020102" +
			"020102300d06092a864886f70d01010b0500300e310c300a0603550403130372" +
			"7361301e170d3136303733303031323335395a170d3236303733303031323335" +
			"395a300e310c300a0603550403130372736130819f300d06092a864886f70d01" +
			"0101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c" +
			"0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19e" +
			"aa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e2" +
			"2a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a" +
			"8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304" +
			"023000300b0603551d0f0404030205a0300d06092a864886f70d01010b050003" +
			"81810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594" +
			"365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd" +
			"335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb" +
			"2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4" +
			"2b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f82" +
			"4cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef78" +
			"0c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671" +
			"459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda" +
			"65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4de" +
			"da4ab42c309572cb7fffee5454b78f0718")

	p := newRecordProtection(recordProtectionTestServerHandshakeSecret)
	inner, err := p.decrypt(NewTLSPlaintext(ContentTypeApplicationData, record[5:]))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	contentType, content := inner.contentType, inner.content
	if contentType != ContentTypeHandshake {
		t.Errorf("content type = %d, want %d", contentType, ContentTypeHandshake)
	}
	recordProtectionTestExpect(t, "content", content, want)
	if p.seq != 1 {
		t.Errorf("seq = %d, want 1", p.seq)
	}
}

func TestRecordProtectionEncryptClientFinished(t *testing.T) {
	finished := recordProtectionTestHex(
		"14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2" +
			"edd5ce61")
	record := recordProtectionTestHex(
		"170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc" +
			"44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546")

	p := newRecordProtection(recordProtectionTestClientHandshakeSecret)
	recordProtectionTestExpect(t, "encrypted record payload", p.encrypt(ContentTypeHandshake, finished), record[5:])
	if p.seq != 1 {
		t.Errorf("seq = %d, want 1", p.seq)
	}
}

func TestRecordProtectionServerApplicationRecords(t *testing.T) {
	tests := []struct {
		name        string
		record      string
		wantType    ContentType
		wantContent string
	}{
		{
			name: "NewSessionTicket (seq 0)",
			record: "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d4" +
				"1d6af8f6b580dcf3d11d63c758db289a015940252f55713e061dc13e078891a3" +
				"8efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e0" +
				"9c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406" +
				"f16e3fc181a77ca475840025db2f0a77f81b5ab05b94c01346755f69232c8651" +
				"9d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74" +
				"bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf159" +
				"85684f",
			wantType: ContentTypeHandshake,
			wantContent: "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec9000000" +
				"00262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785a" +
				"bc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827" +
				"db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529" +
				"513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea61764" +
				"6fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934a" +
				"e4d3570008002a000400000400",
		},
		{
			name: "application data (seq 1)",
			record: "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36" +
				"e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf33254" +
				"0dd032e167c2955d",
			wantType: ContentTypeApplicationData,
			wantContent: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f3031",
		},
		{
			name:        "close_notify alert (seq 2)",
			record:      "1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9",
			wantType:    ContentTypeAlert,
			wantContent: "0100",
		},
	}

	p := newRecordProtection(recordProtectionTestServerApplicationSecret)
	for _, tt := range tests {
		record := recordProtectionTestHex(tt.record)
		inner, err := p.decrypt(NewTLSPlaintext(ContentTypeApplicationData, record[5:]))
		if err != nil {
			t.Fatalf("%s: decrypt: %v", tt.name, err)
		}
		contentType, content := inner.contentType, inner.content
		if contentType != tt.wantType {
			t.Errorf("%s: content type = %d, want %d", tt.name, contentType, tt.wantType)
		}
		recordProtectionTestExpect(t, tt.name, content, recordProtectionTestHex(tt.wantContent))
	}
}

func TestRecordProtectionClientApplicationRecords(t *testing.T) {
	tests := []struct {
		name        string
		contentType ContentType
		content     string
		wantRecord  string
	}{
		{
			name:        "application data (seq 0)",
			contentType: ContentTypeApplicationData,
			content: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f3031",
			wantRecord: "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f" +
				"2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae6" +
				"3aeebb21694915e4",
		},
		{
			name:        "close_notify alert (seq 1)",
			contentType: ContentTypeAlert,
			content:     "0100",
			wantRecord:  "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3",
		},
	}

	p := newRecordProtection(recordProtectionTestClientApplicationSecret)
	for _, tt := range tests {
		got := p.encrypt(tt.contentType, recordProtectionTestHex(tt.content))
		recordProtectionTestExpect(t, tt.name, got, recordProtectionTestHex(tt.wantRecord)[5:])
	}
}

func TestRecordProtectionRoundTrip(t *testing.T) {
	writer := newRecordProtection(recordProtectionTestClientApplicationSecret)
	reader := newRecordProtection(recordProtectionTestClientApplicationSecret)
	for i, msg := range []string{"hello", "", "world"} {
		inner, err := reader.decrypt(NewTLSPlaintext(ContentTypeApplicationData, writer.encrypt(ContentTypeApplicationData, []byte(msg))))
		if err != nil {
			t.Fatalf("record %d: decrypt: %v", i, err)
		}
		contentType, content := inner.contentType, inner.content
		if contentType != ContentTypeApplicationData || string(content) != msg {
			t.Errorf("record %d: got (%d, %q), want (%d, %q)", i, contentType, content, ContentTypeApplicationData, msg)
		}
	}
}

func TestRecordProtectionDecryptErrors(t *testing.T) {
	record := recordProtectionTestHex(
		"17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35e" +
			"df7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78" +
			"b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b" +
			"d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9" +
			"d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2e" +
			"d65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092" +
			"8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead68694" +
			"5ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b368" +
			"4596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f" +
			"4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26" +
			"f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b65962224531" +
			"7b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e" +
			"1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da" +
			"8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d4" +
			"61e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe" +
			"5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb" +
			"992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c859" +
			"77b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038" +
			"ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b84" +
			"5e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5" +
			"d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e" +
			"750edc53370d2b")

	tampered := append([]byte(nil), record[5:]...)
	tampered[0] ^= 0x01
	if _, err := newRecordProtection(recordProtectionTestServerHandshakeSecret).decrypt(NewTLSPlaintext(ContentTypeApplicationData, tampered)); err == nil {
		t.Error("decrypt succeeded on a tampered record, want error")
	}

	if _, err := newRecordProtection(recordProtectionTestClientHandshakeSecret).decrypt(NewTLSPlaintext(ContentTypeApplicationData, record[5:])); err == nil {
		t.Error("decrypt succeeded with the wrong key, want error")
	}

	p := newRecordProtection(recordProtectionTestServerHandshakeSecret)
	p.seq = 1
	if _, err := p.decrypt(NewTLSPlaintext(ContentTypeApplicationData, record[5:])); err == nil {
		t.Error("decrypt succeeded with the wrong sequence number, want error")
	}
}
