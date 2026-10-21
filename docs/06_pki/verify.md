# 証明書チェーンの検証を実装する

本ページでは、サーバーが送ってくるCertificateメッセージを読み、証明書チェーンを検証する処理を実装します。

::: danger 本書が行う検証と行わない検証

本書のクライアントでは、証明書チェーンの検証をGoの`crypto/x509`に任せます。`Verify`メソッドは、[RFC 5280 §6](https://datatracker.ietf.org/doc/html/rfc5280#section-6)に基づく認証パスの検証や、ホスト名の照合などを行います。

ただし、次の2つの確認は行わないため、本書のクライアントは失効した証明書や、TLS 1.3の要件を満たさない証明書を受け入れる可能性があります。

- 証明書が失効していないかの確認（[RFC 5280 §6.3](https://datatracker.ietf.org/doc/html/rfc5280#section-6.3)）
- サーバー証明書に`keyUsage`拡張が存在する場合、`digitalSignature`が設定されているかの確認（[RFC 9846 §4.5.1.2](https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.1.2)）

本書の目的は、証明書検証の基本的な流れを理解することです。そのため、上記2つの確認は実装せず、さらに学習を進めるための発展課題とします。

:::

## Certificateメッセージの構造

証明書チェーンを送るCertificateメッセージの構造は、RFC 9846で次のように定義されています。
> ```c
> struct {
>     opaque certificate_request_context<0..2^8-1>;
>     CertificateEntry certificate_list<0..2^24-1>;
> } Certificate;
> ```
>
> 引用元: [RFC 9846 §4.5.1 Certificate](https://datatracker.ietf.org/doc/html/rfc9846#section-4.5.1)

`certificate_list`には、サーバー証明書を先頭に、DER形式の証明書が並びます。各エントリには証明書本体と拡張が含まれますが、本書では拡張を読み飛ばします。また、サーバーが送るCertificateメッセージでは、`certificate_request_context`は空になります。

## Certificateをパースする関数を実装する

`certificate.go`を作り、Certificateメッセージの本体をパースする`unmarshalCertificate`を実装します。パースには、`bytes.go`に用意した補助関数を使います。

::: code-group

```go [certificate.go]
type certificate struct {
	certificateList [][]byte
}

func unmarshalCertificate(body []byte) (*certificate, error) {
	malformed := errors.New("tls13: malformed Certificate")

	_, rest, ok := readUint8Prefixed(body)
	if !ok {
		return nil, malformed
	}
	list, rest, ok := readUint24Prefixed(rest)
	if !ok || len(rest) != 0 {
		return nil, malformed
	}

	cert := &certificate{}
	for len(list) > 0 {
		certData, r, ok := readUint24Prefixed(list)
		if !ok {
			return nil, malformed
		}
		_, r, ok = readUint16Prefixed(r)
		if !ok {
			return nil, malformed
		}
		cert.certificateList = append(cert.certificateList, append([]byte{}, certData...))
		list = r
	}
	return cert, nil
}
```

:::

`unmarshalCertificate`は、`certificate_request_context`と各エントリの拡張を読み飛ばし、`certificate_list`から証明書のバイト列を順に取り出します。DER形式の証明書の解析は`x509.ParseCertificate`に任せるため、ここでは長さプレフィックスに従ってバイト列を取り出す処理だけを行います。

## 証明書チェーンの検証を状態機械に組み込む

Certificateメッセージの処理は、受信した内容を読み取る処理と、証明書チェーンを検証する処理に分けます。`ReadCertificate`で証明書を読み取り、`VerifyCertificate`で検証します。

### 構造体にフィールドを追加する

`ClientHandshakeState`に、信頼するルート証明書を指定する`roots`と、受信した証明書や検証結果を保持する2つのフィールドを追加します。`roots`が`nil`のときは、OSの信頼済みルート証明書を利用します。`PeerCertificates`と`VerifiedChains`は、`cmd/main.go`から内容を表示できるように公開しておきます。

::: code-group

```go [handshake_client.go]
type ClientHandshakeState struct {
	c          *Conn
	serverName string
	roots      *x509.CertPool // [!code ++]

	// ...

	PeerCertificates []*x509.Certificate // [!code ++]
	VerifiedChains   [][]*x509.Certificate // [!code ++]
}
```

:::

### EncryptedExtensionsをtranscriptに積む処理を実装する

本書ではEncryptedExtensionsの内容を利用しないため、`ReadEncryptedExtensions`から表示処理を削除し、受信したメッセージをtranscriptに追加するようにします。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) ReadEncryptedExtensions() error {
	// ...
	if msg.HandshakeType != TypeEncryptedExtensions {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeEncryptedExtensions, msg.HandshakeType)
	}
	fmt.Printf("EncryptedExtensions: %d bytes\n", len(msg.Body)) // [!code --]
	fmt.Print(hex.Dump(msg.Body)) // [!code --]
	hs.transcript.write(raw)
	return nil
}
```

:::

### Certificateから証明書を取り出す処理を実装する

`ReadCertificate`では、Certificateメッセージをパースして証明書のリストを取り出します。各証明書のDER形式のバイト列を`x509.ParseCertificate`で`x509.Certificate`に変換し、`PeerCertificates`フィールドに保存します。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) ReadCertificate() error {
	// ...
	if msg.HandshakeType != TypeCertificate {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeCertificate, msg.HandshakeType)
	}
	fmt.Printf("Certificate: %d bytes\n", len(msg.Body)) // [!code --]
	fmt.Print(hex.Dump(msg.Body)) // [!code --]
	certificate, err := unmarshalCertificate(msg.Body) // [!code ++]
	if err != nil { // [!code ++]
		return err // [!code ++]
	} // [!code ++]
	if len(certificate.certificateList) == 0 { // [!code ++]
		return errors.New("tls13: server sent no certificates") // [!code ++]
	} // [!code ++]
	certs := make([]*x509.Certificate, len(certificate.certificateList)) // [!code ++]
	for i, der := range certificate.certificateList { // [!code ++]
		if certs[i], err = x509.ParseCertificate(der); err != nil { // [!code ++]
			return err // [!code ++]
		} // [!code ++]
	} // [!code ++]
	hs.PeerCertificates = certs // [!code ++]
	hs.transcript.write(raw)
	return nil
}
```

:::

### 証明書チェーンを検証するメソッドを実装する

`VerifyCertificate`では、`PeerCertificates`に保存した証明書を使って、証明書チェーンを検証します。

検証には`crypto/x509`を使います。`x509.VerifyOptions`の`DNSName`に接続先のホスト名、`Roots`に信頼するルート証明書の集合を指定します。`Roots`が`nil`の場合は、OSの信頼済みルート証明書を利用します。サーバーが送ってきた2枚目以降の証明書は、`Intermediates`に追加します。

そのうえで、1枚目のサーバー証明書の`Verify`メソッドを呼びます。`crypto/x509`は署名や有効期間、ホスト名、証明書の用途などを検証します。

`Verify`メソッドは、検証に成功した証明書チェーンを1つ以上返します。各チェーンはサーバー証明書から始まり、信頼する証明書で終わります。`VerifyCertificate`は、返されたチェーンを`VerifiedChains`フィールドに保存します。

::: code-group

```go [handshake_client.go]
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
```

:::

::: info 中間証明書を送ってこないサーバー

サーバーが検証に必要な中間証明書を送ってこず、クライアントもその証明書を持っていない場合、証明書チェーンを構築できず検証に失敗します。しかし、ブラウザやOSには、不足する中間証明書を取得したり、手元に保存された証明書で補ったりする仕組みがあります。そのため、本書のクライアントでも、OSによっては検証が成功します。こうした動作の違いは、筆者の記事「中間証明書に対する対応が各アプリケーションで異なる話」[^ishida2024-intermediate]と「macOS版cURLはcURLと証明書検証の仕様が異なる」[^ishida2024-macos-curl]で説明しています。

:::

## 本ページで書いたコード

`certificate.go`を作り、`handshake_client.go`を書き換えました。

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

```go [certificate.go]
package tls13

import "errors"

type certificate struct {
	certificateList [][]byte
}

func unmarshalCertificate(body []byte) (*certificate, error) {
	malformed := errors.New("tls13: malformed Certificate")

	_, rest, ok := readUint8Prefixed(body)
	if !ok {
		return nil, malformed
	}
	list, rest, ok := readUint24Prefixed(rest)
	if !ok || len(rest) != 0 {
		return nil, malformed
	}

	cert := &certificate{}
	for len(list) > 0 {
		certData, r, ok := readUint24Prefixed(list)
		if !ok {
			return nil, malformed
		}
		_, r, ok = readUint16Prefixed(r)
		if !ok {
			return nil, malformed
		}
		cert.certificateList = append(cert.certificateList, append([]byte{}, certData...))
		list = r
	}
	return cert, nil
}
```

```go [handshake_client.go]
package tls13

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
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

	PeerCertificates []*x509.Certificate
	VerifiedChains   [][]*x509.Certificate
}

func NewClientHandshakeState(conn net.Conn, serverName string) *ClientHandshakeState {
	return &ClientHandshakeState{
		c:          &Conn{conn: conn},
		serverName: serverName,
		transcript: newTranscript(),
	}
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
	if _, err := hs.c.conn.Write(NewTLSPlaintext(ContentTypeHandshake, raw).Marshal()); err != nil {
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
	fmt.Printf("CertificateVerify: %d bytes\n", len(msg.Body))
	fmt.Print(hex.Dump(msg.Body))
	hs.transcript.write(raw)
	return nil
}
```


:::

[^ishida2024-intermediate]: 石田優希, "中間証明書に対する対応が各アプリケーションで異なる話", さくらのナレッジ, 2024. [Web](https://knowledge.sakura.ad.jp/38997/)

[^ishida2024-macos-curl]: 石田優希, "macOS版cURLはcURLと証明書検証の仕様が異なる", さくらのナレッジ, 2024. [Web](https://knowledge.sakura.ad.jp/38985/)
