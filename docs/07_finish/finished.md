# Finishedを実装する

[第6章](/06_pki/pki)では、サーバーの証明書チェーンとCertificateVerifyの署名を検証しました。本章では、Finishedによってハンドシェイクを完了し、アプリケーションデータを送受信してWebサーバーからHTMLを取得します。最後にパッケージの公開APIを整理し、TLS 1.3クライアントを完成させます。本ページでは、Finishedで鍵とハンドシェイクの内容を確認する仕組みを説明し、検証と送信を実装します。

## Finishedメッセージの構造

サーバーが暗号化して送る一連のハンドシェイクメッセージの最後がFinishedです。メッセージ本体は`verify_data`という1つのフィールドからなり、ハッシュ関数の出力と同じ長さ（SHA-256なら32バイト）のMAC値が入っています。

> ```rust
> struct {
>     opaque verify_data[Hash.length];
> } Finished;
> ```
>
> 引用元: [RFC 9846 §4.5.3 Finished](https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.3)

`verify_data`は、次の手順で計算します。

> ```rust
> finished_key =
>     HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
>
> verify_data =
>     HMAC(finished_key,
>          Transcript-Hash(Handshake Context,
>                          Certificate*, CertificateVerify*))
> ```
>
> 引用元: [RFC 9846 §4.5.3 Finished](https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.3)

BaseKeyにはハンドシェイク用のtraffic secretを使います。サーバーのFinishedでは`server_handshake_traffic_secret`、クライアントのFinishedでは`client_handshake_traffic_secret`から`finished_key`を導出します。HMACの入力はtranscript hashです。サーバーのFinishedではClientHelloからCertificateVerifyまで、クライアントのFinishedではサーバーのFinishedまでを含めて計算します（[RFC 9846 §4.5 Authentication Messages](https://datatracker.ietf.org/doc/html/rfc9846#section-4.5)）。

## Finishedは何を確認しているのか

`finished_key`はハンドシェイク用のtraffic secretから導出します。そのため、正しい`verify_data`を計算するには、対応するtraffic secretが必要です。また、HMACの入力はtranscript hashなので、双方が記録したハンドシェイクメッセージが異なれば検証に失敗します。Finishedの検証では、次の2つを確かめます。

1. 相手が正しいtraffic secretを導出していること。双方の鍵交換と鍵導出の結果が一致している
2. 検証対象となるハンドシェイクメッセージが双方で一致していること。途中で内容が書き換えられていない

CertificateVerifyもそれまでのハンドシェイクの内容を検証するメッセージですが、役割は異なります。CertificateVerifyは証明書の公開鍵に対応する秘密鍵で署名され、通信相手がその秘密鍵を持っていることを示します。一方、Finishedは鍵交換で共有した秘密から導出した鍵でMAC値を計算し、鍵導出の結果とハンドシェイクの内容が一致していることを確かめます。

## アプリケーション鍵への切り替え

クライアントとサーバーはFinishedを交換して検証し、ハンドシェイクを完了すると、アプリケーションデータを送受信できるようになります。

アプリケーションデータの保護には、ハンドシェイク鍵とは別のアプリケーション鍵を使います。この鍵は、Key ScheduleでHandshake Secretの次の段にあるMain Secretから、`client_application_traffic_secret_0`と`server_application_traffic_secret_0`を導出して作ります。2つのtraffic secretの導出に使うtranscript hashには、サーバーのFinishedまでを含め、クライアントのFinishedは含めません。

クライアント側の手順を並べると次のようになります。

1. サーバーのFinishedを検証し、transcriptに積む
2. クライアントのFinishedを計算し、ハンドシェイク鍵で暗号化して送る
3. Main Secretに進み、アプリケーション鍵を導出する

## 実装

### verify_dataを計算する

`key_schedule.go`に、traffic secretとtranscript hashから`verify_data`を計算する関数を追加します。HKDF-Expand-Labelには第4章で実装した`hkdfExpandLabel`を、HMACには`crypto/hmac`を使います。

::: code-group

```go [key_schedule.go]
func finishedVerifyData(trafficSecret, transcriptHash []byte) []byte {
	finishedKey := hkdfExpandLabel(trafficSecret, "finished", nil, sha256.Size)
	mac := hmac.New(sha256.New, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}
```

:::

サーバーのFinishedを検証するときも、クライアントのFinishedを作るときも、渡すtraffic secretが違うだけで計算は同じです。

### サーバーのFinishedを検証する

`handshake_client.go`に`ReadServerFinished`メソッドを追加します。受信した`verify_data`と、クライアントが計算した期待値を比較します。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) ReadServerFinished() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeFinished {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeFinished, msg.HandshakeType)
	}
	want := finishedVerifyData(hs.serverHandshakeTrafficSecret, hs.transcript.sum())
	if !hmac.Equal(msg.Body, want) {
		return errors.New("tls13: invalid server Finished")
	}
	hs.transcript.write(raw)
	return nil
}
```

:::

比較には`hmac.Equal`を使います。通常のバイト列比較では、一致している先頭部分の長さによって処理時間が変わる場合があります。`hmac.Equal`は長さが同じバイト列を定数時間で比較するため、比較結果以外の情報が処理時間から漏れることを防げます。

サーバーのFinishedの計算対象はCertificateVerifyまでのtranscriptです。そのため、`ReadServerFinished`は署名の検証時と同様に、受け取ったFinishedをtranscriptに追加する前に`verify_data`を検証します。

### 送信用の鍵を持たせる

クライアントのFinishedは、ハンドシェイク鍵で暗号化して送る最初のメッセージです。`Conn`に送信用の`recordProtection`を入れる`out`フィールドを足します。

::: code-group

```go [conn.go]
type Conn struct {
	conn         net.Conn
	in           *recordProtection // [!code --]
	in, out      *recordProtection // [!code ++]
	handshakeBuf []byte
}
```

:::

`in`フィールドはサーバーから届くレコードの復号、`out`フィールドはクライアントが送るレコードの暗号化に使います。TLSでは送受信で別々の鍵とシーケンス番号を管理するため、`recordProtection`も方向ごとに用意します。

レコードを送る`writeRecord`メソッドを`conn.go`に足します。`writeRecord`は、`out`フィールドを見て、鍵があればレコードを暗号化して送ります。

::: code-group

```go [conn.go]
func (c *Conn) writeRecord(rec *TLSPlaintext) (err error) {
	if c.out != nil {
		rec = NewTLSPlaintext(ContentTypeApplicationData, c.out.encrypt(rec.Type, rec.Payload))
	}
	_, err = c.conn.Write(rec.Marshal())
	return err
}
```

:::

`out`フィールドが`nil`ならレコードを平文のまま送り、鍵が設定されていれば`encrypt`で暗号化して送ります。暗号化したレコードは、内側に本来の種別を持ち、外側の種別はapplication_dataになります。受信側の`readAndDecryptRecord`と同様に、送信側も鍵の有無によって処理を切り替えます。

ClientHelloを送る`SendClientHello`も、TCPの接続に直接書き込むのをやめ、`writeRecord`で送るように変えます。ClientHelloを送る時点では`out`フィールドが`nil`なので、ClientHelloは平文のまま送られます。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) SendClientHello() error {
	// ...
	if _, err := hs.c.conn.Write(NewTLSPlaintext(ContentTypeHandshake, raw).Marshal()); err != nil { // [!code --]
	if err := hs.c.writeRecord(NewTLSPlaintext(ContentTypeHandshake, raw)); err != nil { // [!code ++]
		return err
	}
	hs.transcript.write(raw)
	return nil
}
```

:::

### クライアントのFinishedを送る

クライアントのFinishedは、`client_handshake_traffic_secret`で作った`verify_data`を、同じ秘密から作った鍵で暗号化して送ります。Finishedの本体は`verify_data`そのものなので、`finishedVerifyData`の返り値をそのまま`NewHandshake`に渡します。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) WriteClientFinished() error {
	msg := NewHandshake(TypeFinished, finishedVerifyData(hs.clientHandshakeTrafficSecret, hs.transcript.sum()))
	hs.c.out = newRecordProtection(hs.clientHandshakeTrafficSecret)
	return hs.c.writeRecord(NewTLSPlaintext(ContentTypeHandshake, msg.Marshal()))
}
```

:::

`WriteClientFinished`は、`client_handshake_traffic_secret`から作った`recordProtection`を`out`フィールドに設定し、`writeRecord`でFinishedを送ります。Finishedは暗号化され、レコードの内側の種別はhandshake、外側の種別はapplication_dataになります。

### アプリケーション鍵に切り替える

Main Secretは、`EstablishHandshakeKeys`が`handshakeSecret`フィールドに保存したHandshake Secretから導き出します。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) SwitchToApplicationKeys() {
	mainSecret := deriveMainSecret(hs.handshakeSecret)
	transcriptHash := hs.transcript.sum()
	hs.c.in = newRecordProtection(deriveSecret(mainSecret, "s ap traffic", transcriptHash))
	hs.c.out = newRecordProtection(deriveSecret(mainSecret, "c ap traffic", transcriptHash))
}
```

:::

`SwitchToApplicationKeys`は、`deriveMainSecret`でMain Secretを導出し、`s ap traffic`と`c ap traffic`のラベルでサーバー用とクライアント用のtraffic secretを導出します。ここで使うtranscript hashは、サーバーのFinishedまでを含む値です。それぞれのtraffic secretから作った`recordProtection`で`Conn`の`in`と`out`を置き換え、レコードの保護をアプリケーション鍵に切り替えます。

### Handshake()に全ステップを並べる

必要な処理が揃ったので、ハンドシェイク全体を1つのメソッドにまとめます。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) Handshake() error {
	if err := hs.GenerateKeyPair(); err != nil {
		return err
	}
	if err := hs.SendClientHello(); err != nil {
		return err
	}
	if err := hs.ReadServerHello(); err != nil {
		return err
	}
	if err := hs.ComputeSharedSecret(); err != nil {
		return err
	}
	hs.EstablishHandshakeKeys()
	if err := hs.ReadEncryptedExtensions(); err != nil {
		return err
	}
	if err := hs.ReadCertificate(); err != nil {
		return err
	}
	if err := hs.VerifyCertificate(); err != nil {
		return err
	}
	if err := hs.ReadCertificateVerify(); err != nil {
		return err
	}
	if err := hs.VerifyCertificateVerify(); err != nil {
		return err
	}
	if err := hs.ReadServerFinished(); err != nil {
		return err
	}
	if err := hs.WriteClientFinished(); err != nil {
		return err
	}
	hs.SwitchToApplicationKeys()
	return nil
}
```

:::

各メソッドは、第1章のハンドシェイク図に沿って並んでいます。`Handshake`メソッドがエラーなく返れば、ハンドシェイクは完了です。

## 本ページで書いたコード

`key_schedule.go`、`conn.go`、`handshake_client.go`を書き換えました。

::: code-group

```[tree]
.
├── cmd/
│   └── main.go
├── go.mod
├── aead.go
├── bytes.go
├── certificate.go
├── client_hello.go
├── common.go
├── conn.go
├── extensions.go
├── handshake.go
├── handshake_client.go
├── key_schedule.go
├── record.go
├── record_protection.go
└── server_hello.go
```

```go [key_schedule.go]
package tls13

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

type transcript struct {
	h hash.Hash
}

func newTranscript() *transcript {
	return &transcript{h: sha256.New()}
}

func (t *transcript) write(msg []byte) {
	t.h.Write(msg)
}

func (t *transcript) sum() []byte {
	return t.h.Sum(nil)
}

func hkdfExtract(salt, ikm []byte) []byte {
	secret, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic(err)
	}
	return secret
}

func deriveSecret(secret []byte, label string, transcriptHash []byte) []byte {
	return hkdfExpandLabel(secret, label, transcriptHash, sha256.Size)
}

func deriveEarlySecret() []byte {
	zeros := make([]byte, sha256.Size)
	return hkdfExtract(zeros, zeros)
}

func deriveHandshakeSecret(sharedSecret []byte) []byte {
	emptyHash := sha256.Sum256(nil)
	salt := deriveSecret(deriveEarlySecret(), "derived", emptyHash[:])
	return hkdfExtract(salt, sharedSecret)
}

func deriveMainSecret(handshakeSecret []byte) []byte {
	emptyHash := sha256.Sum256(nil)
	salt := deriveSecret(handshakeSecret, "derived", emptyHash[:])
	return hkdfExtract(salt, make([]byte, sha256.Size))
}

type hkdfLabel struct {
	length  uint16
	label   string
	context []byte
}

func newHkdfLabel(label string, context []byte, length int) *hkdfLabel {
	return &hkdfLabel{
		length:  uint16(length),
		label:   "tls13 " + label,
		context: context,
	}
}

func (l *hkdfLabel) marshal() []byte {
	b := appendUint16(nil, l.length)
	b = append(b, withUint8Length([]byte(l.label))...)
	return append(b, withUint8Length(l.context)...)
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	hkdfLabel := newHkdfLabel(label, context, length)
	out, err := hkdf.Expand(sha256.New, secret, string(hkdfLabel.marshal()), length)
	if err != nil {
		panic(err)
	}
	return out
}

func trafficKeys(secret []byte) (key, iv []byte) {
	key = hkdfExpandLabel(secret, "key", nil, 16)
	iv = hkdfExpandLabel(secret, "iv", nil, 12)
	return key, iv
}

func finishedVerifyData(trafficSecret, transcriptHash []byte) []byte {
	finishedKey := hkdfExpandLabel(trafficSecret, "finished", nil, sha256.Size)
	mac := hmac.New(sha256.New, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}
```

```go [conn.go]
package tls13

import (
	"fmt"
	"net"
)

type Conn struct {
	conn         net.Conn
	in, out      *recordProtection
	handshakeBuf []byte
}

func (c *Conn) readAndDecryptRecord() (rec *TLSPlaintext, err error) {
	for {
		rec, err = ReadRecord(c.conn)
		if err != nil {
			return nil, err
		}
		if rec.Type != ContentTypeChangeCipherSpec {
			break
		}
	}
	if c.in == nil {
		return rec, nil
	}
	if rec.Type != ContentTypeApplicationData {
		return nil, fmt.Errorf("tls13: unexpected plaintext record type %d", rec.Type)
	}
	inner, err := c.in.decrypt(rec)
	if err != nil {
		return nil, err
	}
	return NewTLSPlaintext(inner.contentType, inner.content), nil
}

func (c *Conn) readHandshake() (msg *Handshake, raw []byte, err error) {
	for !hasCompleteHandshake(c.handshakeBuf) {
		rec, err := c.readAndDecryptRecord()
		if err != nil {
			return nil, nil, err
		}
		switch rec.Type {
		case ContentTypeHandshake:
			c.handshakeBuf = append(c.handshakeBuf, rec.Payload...)
		case ContentTypeAlert:
			return nil, nil, fmt.Errorf("tls13: received alert record: % x", rec.Payload)
		default:
			return nil, nil, fmt.Errorf("tls13: unexpected record type %d during handshake", rec.Type)
		}
	}
	n := 4 + handshakeBodyLen(c.handshakeBuf)
	raw = c.handshakeBuf[:n]
	c.handshakeBuf = c.handshakeBuf[n:]
	msg, err = UnmarshalHandshake(raw)
	if err != nil {
		return nil, nil, err
	}
	return msg, raw, nil
}

func hasCompleteHandshake(buf []byte) (ok bool) {
	return len(buf) >= 4 && len(buf) >= 4+handshakeBodyLen(buf)
}

func handshakeBodyLen(buf []byte) (bodyLen int) {
	return int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
}

func (c *Conn) writeRecord(rec *TLSPlaintext) (err error) {
	if c.out != nil {
		rec = NewTLSPlaintext(ContentTypeApplicationData, c.out.encrypt(rec.Type, rec.Payload))
	}
	_, err = c.conn.Write(rec.Marshal())
	return err
}
```

```go [handshake_client.go]
package tls13

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
)

type ClientHandshakeState struct {
	c          *Conn
	serverName string
	roots      *x509.CertPool

	transcript *transcript

	privateKey      *ecdh.PrivateKey
	serverPublicKey []byte
	sharedSecret    []byte

	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
	handshakeSecret              []byte

	PeerCertificates                []*x509.Certificate
	VerifiedChains                  [][]*x509.Certificate
	PeerCertificateVerify           *CertificateVerify
	certificateVerifyTranscriptHash []byte
}

func NewClientHandshakeState(conn net.Conn, serverName string, roots *x509.CertPool) *ClientHandshakeState {
	return &ClientHandshakeState{
		c:          &Conn{conn: conn},
		serverName: serverName,
		roots:      roots,
		transcript: newTranscript(),
	}
}

func (hs *ClientHandshakeState) Handshake() error {
	if err := hs.GenerateKeyPair(); err != nil {
		return err
	}
	if err := hs.SendClientHello(); err != nil {
		return err
	}
	if err := hs.ReadServerHello(); err != nil {
		return err
	}
	if err := hs.ComputeSharedSecret(); err != nil {
		return err
	}
	hs.EstablishHandshakeKeys()
	if err := hs.ReadEncryptedExtensions(); err != nil {
		return err
	}
	if err := hs.ReadCertificate(); err != nil {
		return err
	}
	if err := hs.VerifyCertificate(); err != nil {
		return err
	}
	if err := hs.ReadCertificateVerify(); err != nil {
		return err
	}
	if err := hs.VerifyCertificateVerify(); err != nil {
		return err
	}
	if err := hs.ReadServerFinished(); err != nil {
		return err
	}
	if err := hs.WriteClientFinished(); err != nil {
		return err
	}
	hs.SwitchToApplicationKeys()
	return nil
}

func (hs *ClientHandshakeState) GenerateKeyPair() error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	hs.privateKey = privateKey
	return nil
}

func (hs *ClientHandshakeState) SendClientHello() error {
	var random [clientRandomLength]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}

	ch := NewClientHello(random, []Extension{
		SupportedVersionsExtension(),
		ServerNameExtension(hs.serverName),
		SignatureAlgorithmsExtension(),
		SupportedGroupsExtension(),
		KeyShareExtension(hs.privateKey.PublicKey().Bytes()),
	})
	h := NewHandshake(TypeClientHello, ch.Marshal())
	raw := h.Marshal()
	if err := hs.c.writeRecord(NewTLSPlaintext(ContentTypeHandshake, raw)); err != nil {
		return err
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) ReadServerHello() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeServerHello {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeServerHello, msg.HandshakeType)
	}
	sh, err := UnmarshalServerHello(msg.Body)
	if err != nil {
		return err
	}
	if sh.CipherSuite != TLS_AES_128_GCM_SHA256 {
		return fmt.Errorf("tls13: server selected unsupported cipher suite %#x", uint16(sh.CipherSuite))
	}
	if v, ok := sh.SelectedVersion(); !ok || v != TLS_VERSION_1_3 {
		return errors.New("tls13: server did not negotiate TLS 1.3")
	}
	group, serverPublicKey, ok := sh.KeyShare()
	if !ok {
		return errors.New("tls13: server did not send a key share")
	}
	if group != X25519 {
		return fmt.Errorf("tls13: server selected unsupported group %#x", uint16(group))
	}
	hs.serverPublicKey = serverPublicKey
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) ComputeSharedSecret() error {
	serverPub, err := ecdh.X25519().NewPublicKey(hs.serverPublicKey)
	if err != nil {
		return err
	}
	hs.sharedSecret, err = hs.privateKey.ECDH(serverPub)
	return err
}

func (hs *ClientHandshakeState) EstablishHandshakeKeys() {
	hs.handshakeSecret = deriveHandshakeSecret(hs.sharedSecret)
	transcriptHash := hs.transcript.sum()
	hs.clientHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "c hs traffic", transcriptHash)
	hs.serverHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "s hs traffic", transcriptHash)
	hs.c.in = newRecordProtection(hs.serverHandshakeTrafficSecret)
}

func (hs *ClientHandshakeState) ReadEncryptedExtensions() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeEncryptedExtensions {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeEncryptedExtensions, msg.HandshakeType)
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) ReadCertificate() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeCertificate {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeCertificate, msg.HandshakeType)
	}
	certificate, err := unmarshalCertificate(msg.Body)
	if err != nil {
		return err
	}
	if len(certificate.certificateList) == 0 {
		return errors.New("tls13: server sent no certificates")
	}
	certs := make([]*x509.Certificate, len(certificate.certificateList))
	for i, der := range certificate.certificateList {
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return err
		}
	}
	hs.PeerCertificates = certs
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) VerifyCertificate() error {
	certs := hs.PeerCertificates
	opts := x509.VerifyOptions{
		DNSName:       hs.serverName,
		Roots:         hs.roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	chains, err := certs[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("tls13: certificate verification failed: %w", err)
	}
	hs.VerifiedChains = chains
	return nil
}

func (hs *ClientHandshakeState) ReadCertificateVerify() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeCertificateVerify {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeCertificateVerify, msg.HandshakeType)
	}
	cv, err := UnmarshalCertificateVerify(msg.Body)
	if err != nil {
		return err
	}
	hs.PeerCertificateVerify = cv
	hs.certificateVerifyTranscriptHash = hs.transcript.sum()
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) VerifyCertificateVerify() error {
	return hs.PeerCertificateVerify.Verify(hs.PeerCertificates[0], hs.certificateVerifyTranscriptHash)
}

func (hs *ClientHandshakeState) ReadServerFinished() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeFinished {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeFinished, msg.HandshakeType)
	}
	want := finishedVerifyData(hs.serverHandshakeTrafficSecret, hs.transcript.sum())
	if !hmac.Equal(msg.Body, want) {
		return errors.New("tls13: invalid server Finished")
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *ClientHandshakeState) WriteClientFinished() error {
	msg := NewHandshake(TypeFinished, finishedVerifyData(hs.clientHandshakeTrafficSecret, hs.transcript.sum()))
	hs.c.out = newRecordProtection(hs.clientHandshakeTrafficSecret)
	return hs.c.writeRecord(NewTLSPlaintext(ContentTypeHandshake, msg.Marshal()))
}

func (hs *ClientHandshakeState) SwitchToApplicationKeys() {
	mainSecret := deriveMainSecret(hs.handshakeSecret)
	transcriptHash := hs.transcript.sum()
	hs.c.in = newRecordProtection(deriveSecret(mainSecret, "s ap traffic", transcriptHash))
	hs.c.out = newRecordProtection(deriveSecret(mainSecret, "c ap traffic", transcriptHash))
}
```

:::
