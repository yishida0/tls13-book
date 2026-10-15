# Key Scheduleを実装する

本ページでは、HKDF-Expand-LabelとKey Scheduleを`key_schedule.go`に実装します。

## HKDF-Expand-Labelを実装する

RFC 9846は、HKDF-Expand-Labelを次のように定義しています。

> ```c
> HKDF-Expand-Label(Secret, Label, Context, Length) =
>     HKDF-Expand(Secret, HkdfLabel, Length)
>
> Where HkdfLabel is specified as:
>
> struct {
>     uint16 length = Length;
>     opaque label<7..255> = "tls13 " + Label;
>     opaque context<0..255> = Context;
> } HkdfLabel;
> ```
>
> 引用元: [RFC 9846 §7.1 Key Schedule](https://datatracker.ietf.org/doc/html/rfc9846#section-7.1)

HKDF-Expand-Labelは、`HkdfLabel`をバイト列にしてinfoとしてHKDF-Expandに渡す関数です。`hkdfLabel`構造体と、`hkdfExpandLabel`関数の順に実装します。

### HkdfLabelを実装する

RFCの`HkdfLabel`を、そのままGoの`hkdfLabel`構造体にします。TLS 1.3のラベルにはすべて`"tls13 "`が前に付くので、コンストラクタの`newHkdfLabel`で付けます。`label`と`context`は最大255バイトの可変長のフィールドなので、`marshal`メソッドでは`withUint8Length`で先頭に1バイトの長さを付けます。

::: code-group

```go [key_schedule.go]
package tls13

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
```

:::

### hkdfExpandLabelを実装する

`hkdfExpandLabel`は、`newHkdfLabel`で作った`hkdfLabel`構造体を`marshal`メソッドでバイト列にし、そのバイト列を`info`として`hkdf.Expand`に渡します。`hkdf.Expand`は`info`を`string`型で受け取りますが、Goの`string`は任意のバイト列を入れられるので、変換しても中身は変わりません。

::: code-group

```go [key_schedule.go]
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	hkdfLabel := newHkdfLabel(label, context, length)
	out, err := hkdf.Expand(sha256.New, secret, string(hkdfLabel.marshal()), length)
	if err != nil {
		panic(err)
	}
	return out
}
```

:::

## Key Scheduleを組む

Key Scheduleの図を、上から順にGoの関数にします。

### Transcript Hashを計算する

`transcript`は、送受信したHandshakeメッセージを`write`で書き足し、`sum`でその時点のハッシュを返します。`hash.Hash`の`Sum`は状態を変えないので、`sum`を呼んだ後も`write`を続けられます。

Transcript Hashは、ハンドシェイクの途中で何度も必要になります。ハンドシェイク鍵の導出ではServerHelloまで、サーバーのFinishedの検証ではCertificateVerifyまでというように、同じメッセージ列の先頭から途中までのハッシュを、時点を変えて使います。メッセージを溜めておいて毎回まとめてハッシュ化しても同じ値になりますが、SHA-256はデータを何回かに分けて入力しても、まとめて入力したときと同じハッシュ値を返します。そのため、メッセージを届いた順に`Write`でハッシュ関数へ入力していけば、メッセージ全体を持ち続けずに済み、先頭から計算し直す必要もありません。Goの`crypto/tls`も同じ方式です。

::: code-group

```go [key_schedule.go]
package tls13

import (
	"crypto/hkdf"
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
```

:::

### HKDF-ExtractとDerive-Secretを実装する

`hkdfExtract`は、`hkdf.Extract`の引数をRFCの`HKDF-Extract(salt, IKM)`と同じ順に並べ直した関数です。Goの`hkdf.Extract`は`IKM`を先に受け取るので、RFCの式と同じ順で書けるようにしておきます。`deriveSecret`はRFCのDerive-Secretで、ハッシュ長の32バイトを取り出します。

::: code-group

```go [key_schedule.go]
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
```

:::

### 各段の秘密を導出する

`deriveEarlySecret`、`deriveHandshakeSecret`、`deriveMainSecret`は、図のEarly Secret、Handshake Secret、Main Secretの段に対応します。Handshake SecretとMain Secretは、上の段の秘密から`"derived"`で作った値をsaltにしてExtractします。`"derived"`の`Messages`は空なので、`context`には空のバイト列のSHA-256を渡します。

::: code-group

```go [key_schedule.go]
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
```

:::

本書はPSKを使わないので、Early Secretは32バイトのゼロから計算する決まった値です。ただし、Handshake Secretのsaltを作るのに必要なので省略はできません。

## 本ページで書いたコード

::: code-group

```[tree]
.
├── cmd/
│   └── main.go
├── go.mod
├── common.go
├── record.go
├── handshake.go
├── bytes.go
├── client_hello.go
├── extensions.go
├── server_hello.go
└── key_schedule.go
```

```go [key_schedule.go]
package tls13

import (
	"crypto/hkdf"
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
```

:::
