package tls13

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type connTestPeer struct {
	conn net.Conn
	in   *recordProtection
	out  *recordProtection
}

func newConnTestPair(t *testing.T) (*Conn, *connTestPeer) {
	t.Helper()
	clientSecret := bytes.Repeat([]byte{0x11}, 32)
	serverSecret := bytes.Repeat([]byte{0x22}, 32)
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() {
		clientSide.Close()
		serverSide.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	clientSide.SetDeadline(deadline)
	serverSide.SetDeadline(deadline)
	c := &Conn{
		conn: clientSide,
		in:   newRecordProtection(serverSecret),
		out:  newRecordProtection(clientSecret),
	}
	peer := &connTestPeer{
		conn: serverSide,
		in:   newRecordProtection(clientSecret),
		out:  newRecordProtection(serverSecret),
	}
	return c, peer
}

func (p *connTestPeer) writeEncrypted(contentType contentType, content []byte) {
	p.writePlaintext(contentTypeApplicationData, p.out.encrypt(contentType, content))
}

func (p *connTestPeer) writePlaintext(contentType contentType, payload []byte) {
	p.conn.Write(newTLSPlaintext(contentType, payload).marshal())
}

func (p *connTestPeer) readEncrypted(t *testing.T) (contentType, []byte) {
	t.Helper()
	rec, err := readRecord(p.conn)
	if err != nil {
		t.Fatalf("peer ReadRecord: %v", err)
	}
	if rec.contentType != contentTypeApplicationData {
		t.Fatalf("outer record type = %d, want %d", rec.contentType, contentTypeApplicationData)
	}
	inner, err := p.in.decrypt(rec)
	if err != nil {
		t.Fatalf("peer decrypt: %v", err)
	}
	innerType, content := inner.contentType, inner.content
	return innerType, content
}

func TestConnWriteEncryptsApplicationData(t *testing.T) {
	c, peer := newConnTestPair(t)
	messages := [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n"), []byte("second record")}
	errc := make(chan error, 1)
	go func() {
		for _, m := range messages {
			n, err := c.Write(m)
			if err != nil {
				errc <- err
				return
			}
			if n != len(m) {
				errc <- fmt.Errorf("Write returned n = %d, want %d", n, len(m))
				return
			}
		}
		errc <- nil
	}()
	for _, want := range messages {
		innerType, got := peer.readEncrypted(t)
		if innerType != contentTypeApplicationData {
			t.Errorf("inner type = %d, want %d", innerType, contentTypeApplicationData)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("peer received %q, want %q", got, want)
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("Write: %v", err)
	}
}

func TestConnWriteSplitsLargeData(t *testing.T) {
	c, peer := newConnTestPair(t)
	data := bytes.Repeat([]byte{'a'}, maxPlaintextLen+100)
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := c.Write(data)
		done <- result{n, err}
	}()
	for _, wantLen := range []int{maxPlaintextLen, 100} {
		if _, got := peer.readEncrypted(t); len(got) != wantLen {
			t.Errorf("peer received a record of %d bytes, want %d", len(got), wantLen)
		}
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("Write: %v", r.err)
	}
	if r.n != len(data) {
		t.Errorf("Write returned n = %d, want %d", r.n, len(data))
	}
}

func TestConnReadReturnsApplicationData(t *testing.T) {
	c, peer := newConnTestPair(t)
	want := []byte("HTTP/1.1 200 OK\r\n\r\n")
	go func() {
		peer.writePlaintext(contentTypeChangeCipherSpec, []byte{1})
		peer.writeEncrypted(contentTypeHandshake, []byte{4, 0, 0, 0})
		peer.writeEncrypted(contentTypeApplicationData, want)
	}()
	got := make([]byte, 64)
	n, err := c.Read(got)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Errorf("Read = %q, want %q", got[:n], want)
	}
}

func TestConnReadKeepsRestOfRecord(t *testing.T) {
	c, peer := newConnTestPair(t)
	want := []byte("HTTP/1.1 200 OK\r\n\r\n")
	go peer.writeEncrypted(contentTypeApplicationData, want)
	first := make([]byte, 4)
	if _, err := io.ReadFull(c, first); err != nil {
		t.Fatalf("Read: %v", err)
	}
	rest := make([]byte, len(want)-len(first))
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := append(first, rest...); !bytes.Equal(got, want) {
		t.Errorf("Read = %q, want %q", got, want)
	}
}

func TestConnReadReturnsEOFOnCloseNotify(t *testing.T) {
	c, peer := newConnTestPair(t)
	go peer.writeEncrypted(contentTypeAlert, []byte{1, 0})
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read error = %v, want io.EOF", err)
	}
}

func TestConnReadReturnsAlert(t *testing.T) {
	c, peer := newConnTestPair(t)
	go peer.writeEncrypted(contentTypeAlert, []byte{2, 40})
	_, err := c.Read(make([]byte, 1))
	var alert *alert
	if !errors.As(err, &alert) {
		t.Fatalf("Read error = %v, want *Alert", err)
	}
	if alert.level != 2 || alert.description != 40 {
		t.Errorf("alert = level %d, description %d, want level 2, description 40", alert.level, alert.description)
	}
}

func TestConnReadRejectsPlaintextRecord(t *testing.T) {
	c, peer := newConnTestPair(t)
	go peer.writePlaintext(contentTypeAlert, []byte{2, 40})
	_, err := c.Read(make([]byte, 1))
	var alert *alert
	if err == nil || errors.As(err, &alert) {
		t.Fatalf("Read error = %v, want an error for a plaintext record after keys", err)
	}
}

func TestConnReadRejectsTamperedRecord(t *testing.T) {
	c, peer := newConnTestPair(t)
	go func() {
		ciphertext := peer.out.encrypt(contentTypeApplicationData, []byte("hello"))
		ciphertext[0] ^= 0xff
		peer.writePlaintext(contentTypeApplicationData, ciphertext)
	}()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read accepted a tampered record")
	}
}

func TestConnCloseSendsCloseNotify(t *testing.T) {
	c, peer := newConnTestPair(t)
	errc := make(chan error, 1)
	go func() { errc <- c.Close() }()
	innerType, content := peer.readEncrypted(t)
	if innerType != contentTypeAlert {
		t.Errorf("inner type = %d, want %d", innerType, contentTypeAlert)
	}
	if !bytes.Equal(content, []byte{1, 0}) {
		t.Errorf("alert = %v, want [1 0] (warning, close_notify)", content)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := peer.conn.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("peer read after Close = %v, want io.EOF", err)
	}
}

func TestConnCloseBeforeHandshake(t *testing.T) {
	c, peer := newConnTestPair(t)
	c.out = nil
	errc := make(chan error, 1)
	go func() { errc <- c.Close() }()
	if n, err := peer.conn.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("peer read = %d bytes, %v, want io.EOF without any record", n, err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Close: %v", err)
	}
}

var (
	connTestServerHello = connTestHex(
		"020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155" +
			"772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb" +
			"f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304")
	connTestEncryptedExtensions = connTestHex(
		"080000240022000a00140012001d00170018001901000101010201030104001c" +
			"0002400100000000")
	connTestCertificate = connTestHex(
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
	connTestCertificateVerify = connTestHex(
		"0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145a" +
			"b3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248ee" +
			"aaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c" +
			"9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea2" +
			"0d53dfacd42f74f3")
	connTestFinished = connTestHex(
		"140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454" +
			"b78f0718")
	connTestServerHandshakeSecret = connTestHex(
		"b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	connTestEncryptedRecord = connTestHex(
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
)

func connTestHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func connTestServerApplicationProtectionAtSeq2() *recordProtection {
	p := newRecordProtection(connTestHex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"))
	p.seq = 2
	return p
}

type connTestStream struct {
	net.Conn
	r io.Reader
	w bytes.Buffer
}

func (s *connTestStream) Read(p []byte) (n int, err error) {
	return s.r.Read(p)
}

func (s *connTestStream) Write(p []byte) (n int, err error) {
	return s.w.Write(p)
}

func connTestConn(stream []byte, in *recordProtection) (c *Conn, s *connTestStream) {
	s = &connTestStream{r: bytes.NewReader(stream)}
	return &Conn{conn: s, in: in}, s
}

func connTestRecord(contentType contentType, payload []byte) []byte {
	return newTLSPlaintext(contentType, payload).marshal()
}

func connTestExpect(t *testing.T, c *Conn, wantType handshakeType, wantRaw []byte) {
	t.Helper()
	h, raw, err := c.readHandshake()
	if err != nil {
		t.Fatalf("readHandshake: %v", err)
	}
	if h.handshakeType != wantType {
		t.Errorf("HandshakeType = %d, want %d", h.handshakeType, wantType)
	}
	if !bytes.Equal(raw, wantRaw) {
		t.Errorf("raw\n got: %x\nwant: %x", raw, wantRaw)
	}
	if !bytes.Equal(h.body, wantRaw[4:]) {
		t.Errorf("Body\n got: %x\nwant: %x", h.body, wantRaw[4:])
	}
}

func TestConnReadHandshakeSingleRecord(t *testing.T) {
	c, _ := connTestConn(connTestRecord(contentTypeHandshake, connTestServerHello), nil)
	connTestExpect(t, c, typeServerHello, connTestServerHello)
	if _, _, err := c.readHandshake(); !errors.Is(err, io.EOF) {
		t.Errorf("readHandshake at end of stream: err = %v, want io.EOF", err)
	}
}

func TestConnReadHandshakeMessageSplitAcrossRecords(t *testing.T) {
	sh := connTestServerHello
	var stream []byte
	stream = append(stream, connTestRecord(contentTypeHandshake, sh[:2])...)
	stream = append(stream, connTestRecord(contentTypeHandshake, sh[2:40])...)
	stream = append(stream, connTestRecord(contentTypeHandshake, sh[40:])...)

	c, _ := connTestConn(stream, nil)
	connTestExpect(t, c, typeServerHello, sh)
}

func TestConnReadHandshakeMultipleMessagesInOneRecord(t *testing.T) {
	var payload []byte
	payload = append(payload, connTestServerHello...)
	payload = append(payload, connTestEncryptedExtensions...)

	c, _ := connTestConn(connTestRecord(contentTypeHandshake, payload), nil)
	connTestExpect(t, c, typeServerHello, connTestServerHello)
	connTestExpect(t, c, typeEncryptedExtensions, connTestEncryptedExtensions)
}

func TestConnReadHandshakeSkipsChangeCipherSpec(t *testing.T) {
	var stream []byte
	stream = append(stream, connTestRecord(contentTypeChangeCipherSpec, []byte{0x01})...)
	stream = append(stream, connTestRecord(contentTypeHandshake, connTestServerHello)...)

	c, _ := connTestConn(stream, nil)
	connTestExpect(t, c, typeServerHello, connTestServerHello)
}

func TestConnReadHandshakeEncryptedHandshake(t *testing.T) {
	var stream []byte
	stream = append(stream, connTestRecord(contentTypeChangeCipherSpec, []byte{0x01})...)
	stream = append(stream, connTestEncryptedRecord...)

	c, _ := connTestConn(stream, newRecordProtection(connTestServerHandshakeSecret))

	tests := []struct {
		name    string
		msgType handshakeType
		want    []byte
	}{
		{"EncryptedExtensions", typeEncryptedExtensions, connTestEncryptedExtensions},
		{"Certificate", typeCertificate, connTestCertificate},
		{"CertificateVerify", typeCertificateVerify, connTestCertificateVerify},
		{"Finished", typeFinished, connTestFinished},
	}
	for _, tt := range tests {
		h, raw, err := c.readHandshake()
		if err != nil {
			t.Fatalf("readHandshake(%s): %v", tt.name, err)
		}
		if h.handshakeType != tt.msgType {
			t.Errorf("%s: HandshakeType = %d, want %d", tt.name, h.handshakeType, tt.msgType)
		}
		if !bytes.Equal(raw, tt.want) {
			t.Errorf("%s: raw\n got: %x\nwant: %x", tt.name, raw, tt.want)
		}
	}
	if _, _, err := c.readHandshake(); !errors.Is(err, io.EOF) {
		t.Errorf("readHandshake at end of stream: err = %v, want io.EOF", err)
	}
}

func TestConnReadHandshakeErrors(t *testing.T) {
	tests := []struct {
		name       string
		stream     []byte
		protection *recordProtection
	}{
		{
			name:   "alert record",
			stream: connTestRecord(contentTypeAlert, []byte{0x02, 0x28}),
		},
		{
			name:   "encrypted record before keys",
			stream: connTestEncryptedRecord,
		},
		{
			name:       "plaintext handshake after keys",
			stream:     connTestRecord(contentTypeHandshake, connTestServerHello),
			protection: newRecordProtection(connTestServerHandshakeSecret),
		},
		{
			name:       "encrypted record with plaintext handshake type",
			stream:     append([]byte{byte(contentTypeHandshake)}, connTestEncryptedRecord[1:]...),
			protection: newRecordProtection(connTestServerHandshakeSecret),
		},
		{
			name:       "encrypted alert record",
			stream:     connTestHex("1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9"),
			protection: connTestServerApplicationProtectionAtSeq2(),
		},
		{
			name:   "unknown record type",
			stream: connTestRecord(contentType(99), []byte{0x00}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := connTestConn(tt.stream, tt.protection)
			h, _, err := c.readHandshake()
			if err == nil {
				t.Fatalf("readHandshake: want error, got message type %d", h.handshakeType)
			}
			if errors.Is(err, io.EOF) {
				t.Errorf("readHandshake: got io.EOF, want an error for the record itself")
			}
		})
	}
}

func TestConnReadHandshakeTruncatedMessage(t *testing.T) {
	c, _ := connTestConn(connTestRecord(contentTypeHandshake, connTestServerHello[:10]), nil)
	if h, _, err := c.readHandshake(); err == nil {
		t.Errorf("readHandshake: want error, got message type %d", h.handshakeType)
	}
}

func TestConnWriteRecord(t *testing.T) {
	c, s := connTestConn(nil, nil)
	if err := c.writeRecord(newTLSPlaintext(contentTypeHandshake, connTestServerHello)); err != nil {
		t.Fatalf("writeRecord: %v", err)
	}
	want := connTestRecord(contentTypeHandshake, connTestServerHello)
	if !bytes.Equal(s.w.Bytes(), want) {
		t.Errorf("written\n got: %x\nwant: %x", s.w.Bytes(), want)
	}
}

func TestConnWriteRecordEncrypts(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, 32)
	c, s := connTestConn(nil, nil)
	c.out = newRecordProtection(secret)
	if err := c.writeRecord(newTLSPlaintext(contentTypeHandshake, connTestFinished)); err != nil {
		t.Fatalf("writeRecord: %v", err)
	}
	rec, err := readRecord(&s.w)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.contentType != contentTypeApplicationData {
		t.Errorf("outer type = %d, want %d", rec.contentType, contentTypeApplicationData)
	}
	inner, err := newRecordProtection(secret).decrypt(rec)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if inner.contentType != contentTypeHandshake || !bytes.Equal(inner.content, connTestFinished) {
		t.Errorf("inner = type %d %x, want type %d %x", inner.contentType, inner.content, contentTypeHandshake, connTestFinished)
	}
}

func TestConnAuthenticatesReceivedHeader(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	ciphertext := newRecordProtection(secret).encrypt(contentTypeApplicationData, []byte("hello"))
	for _, tamper := range []bool{false, true} {
		wire := newTLSPlaintext(contentTypeApplicationData, ciphertext).marshal()
		if tamper {
			wire[2] ^= 1
		}
		c, _ := connTestConn(wire, newRecordProtection(secret))
		rec, err := c.readAndDecryptRecord()
		if tamper {
			if err == nil {
				t.Fatal("accepted an encrypted record with a modified version byte")
			}
		} else if err != nil || !bytes.Equal(rec.payload, []byte("hello")) {
			t.Fatalf("unmodified record: rec=%v err=%v", rec, err)
		}
	}
}

func TestConnAuthenticatesNonstandardLegacyRecordVersion(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	writer := newRecordProtection(secret)
	inner := []byte{'o', 'k', byte(contentTypeApplicationData)}
	header := []byte{0x17, 0x03, 0x02, 0, byte(len(inner) + writer.aead.Overhead())}
	payload := writer.aead.Seal(nil, writer.nextNonce(), inner, header)
	c, _ := connTestConn(append(header, payload...), newRecordProtection(secret))
	rec, err := c.readAndDecryptRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.payload, []byte("ok")) {
		t.Fatalf("payload = %q", rec.payload)
	}
}
