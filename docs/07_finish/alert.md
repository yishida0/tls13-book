# Alertを実装する

現在のクライアントは、サーバーから届く正常な終了通知もエラーとして扱います。本ページでは、接続の正常終了とTLSのエラーを区別できるようにAlertを実装します。`Read`メソッドでAlertを受け取り、`Close`メソッドで終了を通知します。

## Alertプロトコル

Alertは、TLSがエラーや接続の終了を相手に伝えるためのメッセージです。

> ```rust
> enum { warning(1), fatal(2), (255) } AlertLevel;
>
> enum {
>     close_notify(0),
>     unexpected_message(10),
>     bad_record_mac(20),
>     /* （中略） */
>     decrypt_error(51),
>     /* （中略） */
>     (255)
> } AlertDescription;
>
> struct {
>     AlertLevel level;
>     AlertDescription description;
> } Alert;
> ```
>
> 引用元: [RFC 9846 §6 Alert Protocol](https://datatracker.ietf.org/doc/html/rfc9846#section-6)

Alertは、レベルと種別をそれぞれ1バイトで表す、合計2バイトのメッセージです。`level`はTLS 1.2以前との互換性のために残されており、TLS 1.3ではアラートの扱いを`description`で判断します。種別は複数ありますが、ここでは正常終了を伝える`close_notify`と、それ以外のエラー通知に分けて扱います。

`close_notify`が必要なのは、TCPの接続が切れただけでは、相手が正しく送信を終えたのか判断できないためです。

> The client and the server must share knowledge that the connection is ending in order to avoid a truncation attack.
> <br><br>
> 訳）トランケーション攻撃を避けるため、クライアントとサーバーは接続が終了することを互いに知っていなければならない。
>
> 引用元: [RFC 9846 §6.1 Closure Alerts](https://datatracker.ietf.org/doc/html/rfc9846#section-6.1)

通信経路上の攻撃者がTCP接続を途中で切断すると、受信側は残りのデータが存在したことに気付かず、通信が正常に終わったと誤解する可能性があります。このように、データを途中で打ち切る攻撃をトランケーション攻撃と呼びます。`close_notify`はTLSで保護されるため、攻撃者が正しい終了通知を偽造することはできません。TLSでは、通常の終了時に送信側が`close_notify`を送り、受信側が正常終了を確認できるようにしています。

## 実装

### Alertを読み書きする処理を実装する

`alert.go`にAlertを表す`alert`構造体と読み書きする関数を実装し、`common.go`に種別の定数を追加します。本書で定数を定義する種別は`close_notify`だけです。

::: code-group

```go [alert.go]
type alert struct {
	level       uint8
	description alertDescription
}

func (a *alert) Error() string {
	return fmt.Sprintf("tls13: received alert: level %d, description %d", a.level, a.description)
}

func (a *alert) marshal() []byte {
	return []byte{a.level, byte(a.description)}
}

func unmarshalAlert(payload []byte) (*alert, error) {
	if len(payload) != 2 {
		return nil, errors.New("tls13: malformed alert")
	}
	return &alert{level: payload[0], description: alertDescription(payload[1])}, nil
}
```

```go [common.go]
// @see https://datatracker.ietf.org/doc/html/rfc9846#section-6
type alertDescription uint8

const closeNotify alertDescription = 0

const alertLevelWarning = 1
```

:::

`alert`構造体に`Error`メソッドを実装して`error`インターフェースを満たすようにします。これにより、受信したアラートを呼び出し元へエラーとして返せます。

### Readでアラートを受け取る処理を実装する

`Read`メソッドの`switch`にalertの処理を追加します。受け取ったアラートは`alertError`メソッドで`io.EOF`かエラーに変換します。

::: code-group

```go [conn.go]
func (c *Conn) Read(p []byte) (n int, err error) {
	for len(c.appDataBuf) == 0 {
		// ...
		switch rec.Type {
		case ContentTypeApplicationData:
			c.appDataBuf = rec.Payload
		case ContentTypeHandshake:
		case ContentTypeAlert: // [!code ++]
			return 0, c.alertError(rec.Payload) // [!code ++]
		default:
			return 0, fmt.Errorf("tls13: unexpected record type %d", rec.Type)
		}
	}
	// ...
}

func (c *Conn) alertError(payload []byte) error { // [!code ++]
	alert, err := unmarshalAlert(payload) // [!code ++]
	if err != nil { // [!code ++]
		return err // [!code ++]
	} // [!code ++]
	if alert.description == closeNotify { // [!code ++]
		return io.EOF // [!code ++]
	} // [!code ++]
	return alert // [!code ++]
} // [!code ++]
```

:::

`alertError`は、`close_notify`を`io.EOF`に変換します。アプリケーションデータの送受信中に届く`close_notify`は、サーバーがこれ以上データを送らないことを示します。`io.Reader`ではデータの終わりを`io.EOF`で表すため、`Read`メソッドも正常終了として扱います。それ以外のアラートは`*alert`をエラーとして返します。

### Closeでclose_notifyを送る処理を実装する

`Close`メソッドを変更し、`close_notify`を送ってからTCP接続を閉じるようにします。

::: code-group

```go [conn.go]
func (c *Conn) Close() error {
	if c.out != nil { // [!code ++]
		alert := &alert{level: alertLevelWarning, description: closeNotify} // [!code ++]
		c.writeRecord(NewTLSPlaintext(ContentTypeAlert, alert.marshal())) // [!code ++]
	} // [!code ++]
	return c.conn.Close()
}
```

:::

`writeRecord`は、`out`フィールドに設定された鍵でアラートを暗号化して送ります。`out`が`nil`の場合は送信用の鍵が設定されていないため、本書の`Close`メソッドはアラートを送らずにTCP接続を閉じます。AES-128-GCMを使い、詰め物を付けない場合、暗号化した`close_notify`のレコードは、5バイトのヘッダ、2バイトのアラート、1バイトの種別、16バイトの認証タグを合わせた24バイトです。

## 動かす

`cmd/main.go`は変えずに実行します。

::: code-group

```sh [ターミナル]
$ go run ./cmd https://example.com
HTTP/1.1 200 OK
Content-Type: text/html
...
<!doctype html><html lang="en"><head><title>Example Domain</title>...
```

:::

HTTPリクエストには`Connection: close`を付けているため、サーバーはレスポンスを送り終えると接続を閉じます。サーバーから`close_notify`が届いた場合、`Read`メソッドは`io.EOF`を返し、`io.Copy`はエラーを返さずにコピーを終えます。最後に`defer`で登録した`Close`メソッドがクライアントの`close_notify`を送ってTCP接続を閉じます。

[実装の流れ](/01_overview/roadmap)で目標にした`tls13.Dial`と`Write`、`Read`、`Close`が揃いました。自作のTLS 1.3クライアントを使ってWebサーバーからHTMLを取得できるようになりました。

## 本ページで書いたコード

::: code-group

```[tree]
.
├── cmd/
│   └── main.go
├── go.mod
├── aead.go
├── alert.go
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
	"io"
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
	if c.out != nil {
		alert := &alert{level: alertLevelWarning, description: closeNotify}
		c.writeRecord(NewTLSPlaintext(ContentTypeAlert, alert.marshal()))
	}
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
		case ContentTypeAlert:
			return 0, c.alertError(rec.Payload)
		default:
			return 0, fmt.Errorf("tls13: unexpected record type %d", rec.Type)
		}
	}
	n = copy(p, c.appDataBuf)
	c.appDataBuf = c.appDataBuf[n:]
	return n, nil
}

func (c *Conn) alertError(payload []byte) error {
	alert, err := unmarshalAlert(payload)
	if err != nil {
		return err
	}
	if alert.description == closeNotify {
		return io.EOF
	}
	return alert
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

```go [alert.go]
package tls13

import (
	"errors"
	"fmt"
)

type alert struct {
	level       uint8
	description alertDescription
}

func (a *alert) Error() string {
	return fmt.Sprintf("tls13: received alert: level %d, description %d", a.level, a.description)
}

func (a *alert) marshal() []byte {
	return []byte{a.level, byte(a.description)}
}

func unmarshalAlert(payload []byte) (*alert, error) {
	if len(payload) != 2 {
		return nil, errors.New("tls13: malformed alert")
	}
	return &alert{level: payload[0], description: alertDescription(payload[1])}, nil
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

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-6
type alertDescription uint8

const closeNotify alertDescription = 0

const alertLevelWarning = 1

const maxPlaintextLen = 1 << 14

const maxPayloadLen = 1<<14 + 256
```

:::
