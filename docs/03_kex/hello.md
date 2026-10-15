# ClientHello・ServerHelloの役割

[第2章](/02_record/record)では、TLSのメッセージに共通する入れ物を作りました。本章では、その中身となるメッセージを作ります。
扱うのは、TLSの通信のはじめに交わすClientHelloとServerHelloです。前章で作った入れ物を使って、この2つを送受信できるようにしていきましょう。

## TLSの通信は「初めまして」から

初めて訪れるWebサイトのサーバーと通信する場合などです。
どの暗号方式を使うのかも、暗号化に使う鍵も決まっていません。それを1往復で決めるのが、ClientHelloとServerHelloのやり取りです。

このやり取りで決めることは2つです。

1. 使う道具を合意する: TLSのバージョン、暗号スイート、鍵交換方式、署名アルゴリズム。クライアントが対応しているものを列挙し、サーバーがその中から選ぶ
2. 鍵の材料を交換する: 両者が公開鍵を送り合い、それぞれの手元で同じ共有秘密を計算する 
  
	[第5章](../05_aead/aead.md)で詳しく説明しますが、 TLSでは共通鍵暗号を用いてデータのやり取りを行います。
共通鍵暗号でやり取りを行うには、クライアントとサーバーが同じ鍵を持っていなければなりません。
その鍵を作るために、ClientHelloとServerHelloのやり取りで公開鍵を交換し、両者が同じ共有秘密を計算します。

## ClientHelloのデータ構造

早速ClientHelloの構造から見て行きましょう。RFCにおけるClientHelloの定義は以下の通りです。

> ```c
> struct {
>     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
>     Random random;
>     opaque legacy_session_id<0..32>;
>     CipherSuite cipher_suites<2..2^16-2>;
>     opaque legacy_compression_methods<1..2^8-1>;
>     Extension extensions<7..2^16-1>;
> } ClientHello;
> ```
>
> 引用元: [RFC 9846 §4.2.2 Client Hello](https://datatracker.ietf.org/doc/html/rfc9846#section-4.2.2)

![ClientHelloのフィールドと長さの並び](./img/9.svg)

::: tip 長さフィールドが必要かどうかの見分け方
ClientHelloのstructには長さフィールドが1つも書かれていませんが、実際のバイト列には入ります。型名の後ろの記法から判断できます。

`<下限..上限>`が付いていれば可変長で、中身の前に長さが入ります。幅は上限を表すのに必要なバイト数です。

> Variable-length vectors are defined by specifying a subrange of legal lengths, inclusively, using the notation `<floor..ceiling>`. When these are encoded, the actual length precedes the vector's contents in the byte stream. The length will be in the form of a number consuming as many bytes as required to hold the vector's specified maximum (ceiling) length.
> <br><br>
> 訳）可変長ベクタは、`<floor..ceiling>`という記法を用いて、正当な長さの範囲を上下限含めて指定することで定義される。これらが符号化されるとき、実際の長さがバイト列の中でベクタの内容の前に置かれる。長さは、そのベクタに指定された最大長（上限）を保持するのに必要なだけのバイト数を消費する数値の形をとる。
>
> 引用元: [RFC 9846 §3.4 Vectors](https://datatracker.ietf.org/doc/html/rfc9846#section-3.4)

`<0..32>`なら上限32が1バイトに収まるので長さは1バイト、`<2..2^16-2>`なら2バイトです。下限は中身の最小の長さを決める制約なので、幅には関係しません。

`[n]`が付いているものと、`uint16`のような型そのものは固定長で、長さは入りません。

> The length of the vector is not included in the encoded stream.
> <br><br>
> 訳）ベクタの長さは符号化されたストリームには含まれない。
>
> 引用元: [RFC 9846 §3.4 Vectors](https://datatracker.ietf.org/doc/html/rfc9846#section-3.4)

ClientHelloの6つのフィールドに当てはめると、長さが入るのは`legacy_session_id`（1バイト）、`cipher_suites`（2バイト）、`legacy_compression_methods`（1バイト）、`extensions`（2バイト）の4つです。`legacy_version`と`random`には入りません。
:::

## ClientHelloの各フィールドの意味と入力する値

| フィールド | 役割 | 本書で入れる値 |
|---|---|---|
| `legacy_version` | TLS 1.2以前のバージョン交渉用。高いバージョン番号を拒否するサーバーに当たらないよう固定値を置く。真のバージョン交渉は`supported_versions`拡張が担う | `0x0303`（TLS 1.2） |
| `random` | 接続ごとに変わる32バイトの乱数。ハンドシェイク全体のハッシュの先頭に入り、以降の鍵導出と署名検証の入力になる | `crypto/rand`で生成 |
| `legacy_session_id` | TLS 1.2のセッション再開に使っていた識別子。TLS 1.3では再開がPSKに統合され、このフィールドに役目はない | 長さ0（互換モードを使わない） |
| `cipher_suites` | レコード保護のアルゴリズムと、HKDFで使うハッシュ関数を優先度の高い順に並べる | `TLS_AES_128_GCM_SHA256`のみ |
| `legacy_compression_methods` | TLS 1.2以前の圧縮方式の一覧。TLS 1.3では圧縮そのものが廃止された | `{0}`（null圧縮） |
| `extensions` | 実質的な交渉はすべてここ。バージョン、鍵交換方式、署名方式の申告に加え、公開鍵と接続先もここで送る | 5つの拡張（次のページ） |

*ClientHelloの各フィールドと本書で入れる値*

::: tip legacyの付くフィールド
6つのフィールドのうち3つに`legacy_`が付いています。どれもTLS 1.3で新しく足されたものではなく、TLS 1.2以前から存在していたフィールドです。TLS 1.2の仕様である[RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.2)では`client_version`、`session_id`、`compression_methods`という名前で、それぞれバージョン交渉、セッション再開、圧縮方式の選択に実際に使われていました。

TLS 1.3は、バージョン交渉を`supported_versions`拡張に移し、セッション再開をPSKの仕組みにまとめ、圧縮を廃止しました。3つのフィールドは役目を終えましたが、TLS 1.3はフィールド自体を残しています。ClientHelloのバイト列をTLS 1.2と同じ形に保つためです。同じ形であれば、経路上の機器もClientHelloを異常なデータとして扱わずに通します。

そのためRFC 9846では、名前の先頭に`legacy_`を付けて「もう意味を持たないが互換性のために残しているフィールド」であることを示し、入れるべき値も固定しています。実質的な交渉はすべて最後の`extensions`に移っています。
:::

## 実装

### 定数を足す

構造体を書く前に、`cipher_suites`の型になる定数を`common.go`に追加します。番号は[IANAのレジストリ](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)で管理されています。
本書ではGoの標準パッケージとして用意されている`TLS_AES_128_GCM_SHA256`のみを使うので、これだけ定義しておきます。

::: code-group

```go [common.go]
// @see https://datatracker.ietf.org/doc/html/rfc9846#appendix-B.4
type CipherSuite uint16

const TLS_AES_128_GCM_SHA256 CipherSuite = 0x1301
```

:::

### 構造体に写す

RFCで定義された構造を、そのままGoの構造体にします。`random`は32バイトの固定長なので、配列で表します。

`Extension`型はまだ定義していないため、この時点ではコンパイルが通りません。次のページで定義するので、ここでは未定義の`Extension`に関するエラーは無視して進めてください。

::: code-group

```go [client_hello.go]
package tls13

const clientRandomLength = 32

type ClientHello struct {
	ProtocolVersion          TLSVersion
	Random                   [clientRandomLength]byte
	LegacySessionID          []byte
	CipherSuites             []CipherSuite
	LegacyCompressionMethods []byte
	Extensions               []Extension
}

func NewClientHello(random [clientRandomLength]byte, exts []Extension) *ClientHello {
	return &ClientHello{
		ProtocolVersion:          TLS_VERSION_1_2,
		Random:                   random,
		LegacySessionID:          nil,
		CipherSuites:             []CipherSuite{TLS_AES_128_GCM_SHA256},
		LegacyCompressionMethods: []byte{0x00},
		Extensions:               exts,
	}
}
```

:::

### ヘルパ関数を用意する

Lengthの計算やuint16からバイト列への変換などの処理が多くなるため、先に小さなヘルパ関数を用意しておきます。`bytes.go`を作ります。

::: code-group

```go [bytes.go]
package tls13

// uint16を2バイトへ分解してbの末尾に書き足す
func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// bodyの前にその長さ(1バイト)を付けて返す
func withUint8Length(body []byte) []byte {
	return append([]byte{byte(len(body))}, body...)
}

// bodyの前にその長さ(2バイト)を付けて返す
func withUint16Length(body []byte) []byte {
	return append([]byte{byte(len(body) >> 8), byte(len(body))}, body...)
}
```

:::

`withUint16Length`は「中身を先に組み立ててから、その長さを前に付ける」という関数です。長さを自分で数える代わりに、組み立てたバイト列を渡せば`len`が長さになります。入れ子は関数の入れ子で表現できます。

### バイト列にする

`Marshal`はstructのフィールド順にバイト列を組み立てます。可変長のフィールドは、中身を先に作ってから`withUint8Length`や`withUint16Length`で包みます。RFCのstructで`<0..32>`のように書かれていたフィールドが、そのまま1行に対応します。

::: code-group

```go [client_hello.go]
func (ch *ClientHello) Marshal() []byte {
	var cipherSuites []byte
	for _, cs := range ch.CipherSuites {
		cipherSuites = appendUint16(cipherSuites, uint16(cs))
	}

	var extensions []byte
	for _, ext := range ch.Extensions {
		extensions = append(extensions, ext.Marshal()...)
	}

	buf := appendUint16(nil, uint16(ch.ProtocolVersion))
	buf = append(buf, ch.Random[:]...)
	buf = append(buf, withUint8Length(ch.LegacySessionID)...)
	buf = append(buf, withUint16Length(cipherSuites)...)
	buf = append(buf, withUint8Length(ch.LegacyCompressionMethods)...)
	return append(buf, withUint16Length(extensions)...)
}
```

:::

## 本ページで書いたコード

::: code-group

```[tree]
.
├── go.mod
├── common.go
├── record.go
├── handshake.go
├── bytes.go
└── client_hello.go
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

const maxPayloadLen = 1<<14 + 256
```

```go [bytes.go]
package tls13

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func withUint8Length(body []byte) []byte {
	return append([]byte{byte(len(body))}, body...)
}

func withUint16Length(body []byte) []byte {
	return append([]byte{byte(len(body) >> 8), byte(len(body))}, body...)
}
```

```go [client_hello.go]
package tls13

const clientRandomLength = 32

type ClientHello struct {
	ProtocolVersion          TLSVersion
	Random                   [clientRandomLength]byte
	LegacySessionID          []byte
	CipherSuites             []CipherSuite
	LegacyCompressionMethods []byte
	Extensions               []Extension
}

func NewClientHello(random [clientRandomLength]byte, exts []Extension) *ClientHello {
	return &ClientHello{
		ProtocolVersion:          TLS_VERSION_1_2,
		Random:                   random,
		LegacySessionID:          nil,
		CipherSuites:             []CipherSuite{TLS_AES_128_GCM_SHA256},
		LegacyCompressionMethods: []byte{0x00},
		Extensions:               exts,
	}
}

func (ch *ClientHello) Marshal() []byte {
	var cipherSuites []byte
	for _, cs := range ch.CipherSuites {
		cipherSuites = appendUint16(cipherSuites, uint16(cs))
	}

	var extensions []byte
	for _, ext := range ch.Extensions {
		extensions = append(extensions, ext.Marshal()...)
	}

	buf := appendUint16(nil, uint16(ch.ProtocolVersion))
	buf = append(buf, ch.Random[:]...)
	buf = append(buf, withUint8Length(ch.LegacySessionID)...)
	buf = append(buf, withUint16Length(cipherSuites)...)
	buf = append(buf, withUint8Length(ch.LegacyCompressionMethods)...)
	return append(buf, withUint16Length(extensions)...)
}
```

:::
