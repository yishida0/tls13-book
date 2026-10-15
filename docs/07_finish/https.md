# アプリケーションデータを送受信する

## ハンドシェイクの後に流れるもの

ハンドシェイクの完了後は、アプリケーション鍵で保護されたレコードを送受信します。暗号化されたレコードの外側の種別はapplication_dataですが、復号するとTLSInnerPlaintextから本来の種別を取り出せます。本書のクライアントが受け取るメッセージは、主に表1の3種類です。

| 内側の種別 | 中身 | 本書での扱い |
|---|---|---|
| application_data | HTTPなど上位層のデータ | 呼び出し元に返す |
| alert | エラーや切断の通知 | エラーとして返す |
| handshake | NewSessionTicketなどハンドシェイク後のメッセージ | 読み捨てる |

*ハンドシェイク後に届くレコードの中身*

NewSessionTicketは、サーバーが後の接続でセッションを再開できるように送るメッセージです（[RFC 9846 §4.7.1 New Session Ticket Message](https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.1)）。本書ではセッション再開を実装しないため、届いても読み捨てます。

## net.Connと同じように扱えるようにする

Goでは、TCPの接続を`net`パッケージの`net.Conn`インターフェースで扱えます。`net.Conn`を使うプログラムは、`Write`でデータを送り、`Read`で受け取り、`Close`で接続を閉じます。

```go
type Conn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	// ...
}
```

標準ライブラリ`crypto/tls`の`tls.Conn`も、`net.Conn`と同じメソッドを持っています。暗号化と復号は`tls.Conn`の内部で行われるため、利用者はTCP接続と同じように`Write`と`Read`を呼ぶことでTLS通信を行えます。

本書の`Conn`にも、`Write`、`Read`、`Close`を実装します。また、`tls13.Dial`でTLS接続を確立できるようにし、呼び出し元が暗号化や復号を意識せずに通信できる形にします。

## 実装

### 平文の長さの上限を表す定数を足す

`common.go`に、1つのレコードに入れられる平文の最大長を表す`maxPlaintextLen`を追加します。

::: code-group

```go [common.go]
const maxPlaintextLen = 1 << 14
```

:::

TLSでは、1つのレコードに入れられる平文は2<sup>14</sup>バイト、つまり16,384バイトまでと決まっています。

> length:  The length (in bytes) of the following TLSPlaintext.fragment.  The length MUST NOT exceed 2^14 bytes.
> <br><br>
> 訳）length：後に続くTLSPlaintext.fragmentの長さ（バイト単位）。長さは2<sup>14</sup>バイトを超えてはならない。
>
> 引用元: [RFC 9846 §5.1 Record Layer](https://datatracker.ietf.org/doc/html/rfc9846#section-5.1)

暗号化するレコードでも、元の平文データの上限は2<sup>14</sup>バイトです。暗号化前のTLSInnerPlaintextには種別の1バイトも加わるため、[RFC 9846 §5.4 Record Padding](https://datatracker.ietf.org/doc/html/rfc9846#section-5.4)では、詰め物を含めたTLSInnerPlaintext全体の長さを2<sup>14</sup> + 1バイトまでとしています。

### Write

`Write`メソッドは、渡されたバイト列をアプリケーションデータとして送ります。

::: code-group

```go [conn.go]
func (c *Conn) Write(p []byte) (n int, err error) {
	for n < len(p) {
		end := min(n+maxPlaintextLen, len(p))
		if err := c.writeRecord(NewTLSPlaintext(ContentTypeApplicationData, p[n:end])); err != nil {
			return n, err
		}
		n = end
	}
	return n, nil
}
```

:::

`Write`メソッドは、渡されたバイト列を`maxPlaintextLen`以下に分割し、`writeRecord`でレコードごとに送信します。`writeRecord`は、`out`フィールドのアプリケーション鍵で暗号化し、外側の種別をapplication_dataにして書き込みます。

`Write`メソッドが返す`n`は、正常に書き込めたバイト数です。途中で書き込みに失敗した場合は、それまでに書き込んだ分のバイト数とエラーを返します。

### Connに読み残しのバッファを足す

`conn.go`の`Conn`に、`appDataBuf`フィールドを足します。

::: code-group

```go [conn.go]
type Conn struct {
	conn         net.Conn
	in, out      *recordProtection
	handshakeBuf []byte
	appDataBuf   []byte // [!code ++]
}
```

:::

`appDataBuf`フィールドは、復号したアプリケーションデータのうち、まだ呼び出し元に渡していないバイト列を溜めるバッファです。

### Read

`Read`メソッドは、受け取ったアプリケーションデータを呼び出し元のバッファ`p`に書き込みます。

::: code-group

```go [conn.go]
func (c *Conn) Read(p []byte) (n int, err error) {
	for len(c.appDataBuf) == 0 {
		rec, err := c.readAndDecryptRecord()
		if err != nil {
			return 0, err
		}
		switch rec.Type {
		case ContentTypeApplicationData:
			c.appDataBuf = rec.Payload
		case ContentTypeHandshake:
		default:
			return 0, fmt.Errorf("tls13: unexpected record type %d", rec.Type)
		}
	}
	n = copy(p, c.appDataBuf)
	c.appDataBuf = c.appDataBuf[n:]
	return n, nil
}
```

:::

レコードの受信と復号は、実装済みの`readAndDecryptRecord`が行います。このメソッドは`change_cipher_spec`を読み飛ばし、`in`フィールドのアプリケーション鍵で復号したあと、内側の種別とデータを持つ`TLSPlaintext`を返します。鍵が設定されている状態で平文のレコードを受信した場合は、エラーを返します。

`Read`メソッドの`switch`では、application_dataを受け取った場合は中身を`appDataBuf`に保存し、handshakeなら読み捨てて次のレコードへ進みます。この段階ではNewSessionTicketなどのハンドシェイク後のメッセージは処理しません。alertを含むその他の種別はエラーにします。

`io.Reader`の`Read`は、レコード全体を一度に返す必要はなく、呼び出し元のバッファ`p`に入るだけのデータを返せます。そこで、`appDataBuf`から`p`に収まる分をコピーし、残りは次の呼び出しまで保持します。`appDataBuf`に読み残しがある間は、新しいレコードを読みません。こうして、レコードの境界と`Read`が返すデータの境界の違いを吸収します。

### Close

`Close`メソッドは、TCPの接続を閉じます。

::: code-group

```go [conn.go]
func (c *Conn) Close() error {
	return c.conn.Close()
}
```

:::

## 接続の設定を表す構造体を実装する

`client.go`を作り、接続の設定を表す`Config`構造体を定義します。

::: code-group

```go [client.go]
type Config struct {
	ServerName string
	RootCAs    *x509.CertPool
}
```

:::

`ServerName`にはサーバー名を指定し、SNIの送信と証明書のホスト名検証に使います。`RootCAs`には信頼するルート証明書を指定します。`RootCAs`が`nil`の場合は、OSのルート証明書ストアを使います。

### 状態機械をConnにつなぎ替える

`conn.go`の`Conn`に、接続の設定を持つ`config`フィールドを足します。

::: code-group

```go [conn.go]
type Conn struct {
	conn         net.Conn
	config       *Config // [!code ++]
	in, out      *recordProtection
	handshakeBuf []byte
	appDataBuf   []byte
}
```

:::

`ClientHandshakeState`が持っていた`serverName`と`roots`は、`Conn`の`config`フィールドに移します。`NewClientHandshakeState`と`Handshake`は、`Conn`の`handshake`メソッドに置き換えます。

::: code-group

```go [handshake_client.go]
type ClientHandshakeState struct {
	c          *Conn
	serverName string // [!code --]
	roots      *x509.CertPool // [!code --]

	transcript *transcript

	// ...
}

func NewClientHandshakeState(conn net.Conn, serverName string, roots *x509.CertPool) *ClientHandshakeState { // [!code --]
	return &ClientHandshakeState{ // [!code --]
		c:          &Conn{conn: conn}, // [!code --]
		serverName: serverName, // [!code --]
		roots:      roots, // [!code --]
		transcript: newTranscript(), // [!code --]
	} // [!code --]
} // [!code --]

func (hs *ClientHandshakeState) Handshake() error { // [!code --]
func (c *Conn) handshake() error { // [!code ++]
	hs := &ClientHandshakeState{ // [!code ++]
		c:          c, // [!code ++]
		transcript: newTranscript(), // [!code ++]
	} // [!code ++]
	if err := hs.GenerateKeyPair(); err != nil {
		return err
	}
	// ...
}
```

:::

`handshake`メソッドは、冒頭で状態機械を組み立ててから、`Handshake`メソッドと同じ順で各手順を呼びます。

`serverName`と`roots`を使っていた`SendClientHello`と`VerifyCertificate`は、`Conn`の`config`フィールドから値を読むように変えます。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) SendClientHello() error {
	// ...
	ch := NewClientHello(random, []Extension{
		SupportedVersionsExtension(),
		ServerNameExtension(hs.serverName), // [!code --]
		ServerNameExtension(hs.c.config.ServerName), // [!code ++]
		SignatureAlgorithmsExtension(),
		SupportedGroupsExtension(),
		KeyShareExtension(hs.privateKey.PublicKey().Bytes()),
	})
	// ...
}

// ...

func (hs *ClientHandshakeState) VerifyCertificate() error {
	certs := hs.PeerCertificates
	opts := x509.VerifyOptions{
		DNSName:       hs.serverName, // [!code --]
		Roots:         hs.roots, // [!code --]
		DNSName:       hs.c.config.ServerName, // [!code ++]
		Roots:         hs.c.config.RootCAs, // [!code ++]
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// ...
}
```

:::

### Dial

`client.go`に、TLS接続を確立する公開関数`Dial`を追加します。

::: code-group

```go [client.go]
func Dial(network, addr string, config *Config) (*Conn, error) {
	raw, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	c := &Conn{conn: raw, config: config}
	if err := c.handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}
```

:::

`Dial`はTCP接続を確立したあとにハンドシェイクを実行し、成功した場合は`Conn`を返します。途中で失敗した場合はTCP接続を閉じ、エラーを返します。

## 動かす

`Dial`で接続し、`fmt.Fprintf`でHTTPリクエストを書き込み、`io.Copy`でレスポンスを標準出力にコピーするコマンドを作ります。

::: code-group

```go [cmd/main.go]
package main

import (
	"fmt"
	"io"
	"net/url"
	"os"

	"tls13"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tlsclient <https-url>")
		os.Exit(1)
	}
	u, err := url.Parse(os.Args[1])
	if err != nil || u.Scheme != "https" {
		fmt.Fprintln(os.Stderr, "error: https URL required")
		os.Exit(1)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}

	conn, err := tls13.Dial("tcp", u.Hostname()+":"+port, &tls13.Config{ServerName: u.Hostname()})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Hostname()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

:::

::: code-group

```sh [ターミナル]
$ go run ./cmd https://example.com
HTTP/1.1 200 OK
Content-Type: text/html
...
<!doctype html><html lang="en"><head><title>Example Domain</title>...
error: tls13: unexpected record type 21
exit status 1
```

:::

サーバーからのHTTPレスポンスが表示され、アプリケーションデータを送受信できたことが分かります。出力の最後にある`unexpected record type 21`は、`Read`メソッドが種別21のalertを受信し、エラーとして返したことを示しています。HTTPリクエストに`Connection: close`を付けているため、サーバーはレスポンスの送信後に接続を閉じます。この例では、その際に送られたalertを`Read`が処理できず、`io.Copy`がエラーを返してプログラムが終了します。

## 本ページで書いたコード

::: code-group

```[tree]
.
├── cmd/
│   └── main.go
├── go.mod
├── aead.go
├── bytes.go
├── certificate.go
├── client.go
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

```go [conn.go]
package tls13

import (
	"fmt"
	"net"
)

type Conn struct {
	conn         net.Conn
	config       *Config
	in, out      *recordProtection
	handshakeBuf []byte
	appDataBuf   []byte
}

func (c *Conn) Write(p []byte) (n int, err error) {
	for n < len(p) {
		end := min(n+maxPlaintextLen, len(p))
		if err := c.writeRecord(NewTLSPlaintext(ContentTypeApplicationData, p[n:end])); err != nil {
			return n, err
		}
		n = end
	}
	return n, nil
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) Read(p []byte) (n int, err error) {
	for len(c.appDataBuf) == 0 {
		rec, err := c.readAndDecryptRecord()
		if err != nil {
			return 0, err
		}
		switch rec.Type {
		case ContentTypeApplicationData:
			c.appDataBuf = rec.Payload
		case ContentTypeHandshake:
		default:
			return 0, fmt.Errorf("tls13: unexpected record type %d", rec.Type)
		}
	}
	n = copy(p, c.appDataBuf)
	c.appDataBuf = c.appDataBuf[n:]
	return n, nil
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

```go [client.go]
package tls13

import (
	"crypto/x509"
	"net"
)

type Config struct {
	ServerName string
	RootCAs    *x509.CertPool
}

func Dial(network, addr string, config *Config) (*Conn, error) {
	raw, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	c := &Conn{conn: raw, config: config}
	if err := c.handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
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
)

type ClientHandshakeState struct {
	c *Conn

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

func (c *Conn) handshake() error {
	hs := &ClientHandshakeState{
		c:          c,
		transcript: newTranscript(),
	}
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
		ServerNameExtension(hs.c.config.ServerName),
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
		DNSName:       hs.c.config.ServerName,
		Roots:         hs.c.config.RootCAs,
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

```go [common.go]
package tls13

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-5.1
type ContentType uint8

const (
	ContentTypeChangeCipherSpec ContentType = 20
	ContentTypeAlert            ContentType = 21
	ContentTypeHandshake        ContentType = 22
	ContentTypeApplicationData  ContentType = 23
)

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4.2.2
type TLSVersion uint16

const (
	TLS_VERSION_1_2 TLSVersion = 0x0303
	TLS_VERSION_1_3 TLSVersion = 0x0304
)

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4
type HandshakeType uint8

const (
	TypeClientHello         HandshakeType = 1
	TypeServerHello         HandshakeType = 2
	TypeEncryptedExtensions HandshakeType = 8
	TypeCertificate         HandshakeType = 11
	TypeCertificateVerify   HandshakeType = 15
	TypeFinished            HandshakeType = 20
)

// @see https://datatracker.ietf.org/doc/html/rfc9846#appendix-B.4
type CipherSuite uint16

const TLS_AES_128_GCM_SHA256 CipherSuite = 0x1301

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4.3
type extensionType uint16

const (
	extServerName          extensionType = 0
	extSupportedGroups     extensionType = 10
	extSignatureAlgorithms extensionType = 13
	extSupportedVersions   extensionType = 43
	extKeyShare            extensionType = 51
)

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.7
type NamedGroup uint16

const X25519 NamedGroup = 0x001d

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.3
type SignatureScheme uint16

const (
	RSA_PKCS1_SHA256       SignatureScheme = 0x0401
	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
	ECDSA_SECP384R1_SHA384 SignatureScheme = 0x0503
	RSA_PSS_RSAE_SHA256    SignatureScheme = 0x0804
	RSA_PSS_RSAE_SHA384    SignatureScheme = 0x0805
	RSA_PSS_RSAE_SHA512    SignatureScheme = 0x0806
)

const maxPlaintextLen = 1 << 14

const maxPayloadLen = 1<<14 + 256
```

```go [cmd/main.go]
package main

import (
	"fmt"
	"io"
	"net/url"
	"os"

	"tls13"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tlsclient <https-url>")
		os.Exit(1)
	}
	u, err := url.Parse(os.Args[1])
	if err != nil || u.Scheme != "https" {
		fmt.Fprintln(os.Stderr, "error: https URL required")
		os.Exit(1)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}

	conn, err := tls13.Dial("tcp", u.Hostname()+":"+port, &tls13.Config{ServerName: u.Hostname()})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Hostname()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

:::
