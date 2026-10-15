# ハンドシェイクを状態機械にまとめる

本ページでは、これまで作成してきた処理を状態機械としてまとめます。

ハンドシェイクの状態は`ClientHandshakeState`構造体のフィールドに保持し、各手順をメソッドとして実装します。メソッドは、それまでの状態を使って1つの処理を実行し、結果を状態に保存します。メソッドを順に呼び出すことで、ハンドシェイクを1段ずつ進めます。

## 実装

### ハンドシェイクの状態を管理する構造体を作る

まず、クライアントのハンドシェイクの状態を管理する`ClientHandshakeState`構造体を、`handshake_client.go`に定義します。

構造体には、TCPの接続を扱う`Conn`、サーバー名、transcript、鍵交換の秘密鍵と公開鍵、共有秘密、handshake traffic secretなどを保持します。

::: code-group

```go [handshake_client.go]
type ClientHandshakeState struct {
	c          *Conn
	serverName string

	transcript *transcript

	privateKey      *ecdh.PrivateKey
	serverPublicKey []byte
	sharedSecret    []byte

	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
	handshakeSecret              []byte
}

func NewClientHandshakeState(conn net.Conn, serverName string) *ClientHandshakeState {
	return &ClientHandshakeState{
		c:          &Conn{conn: conn},
		serverName: serverName,
		transcript: newTranscript(),
	}
}
```

:::


続いて、ClientHelloの組み立て、ServerHelloのパース、共有秘密の計算、handshake traffic secretの導出を、それぞれメソッドにまとめます。

### 鍵ペアを作るメソッドの実装

`GenerateKeyPair`は、X25519の鍵ペアを作り、秘密鍵を`privateKey`フィールドに入れます。公開鍵は秘密鍵の`PublicKey`メソッドで取り出せるので、フィールドには持たせません。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) GenerateKeyPair() error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	hs.privateKey = privateKey
	return nil
}
```

:::

### ClientHelloを送るメソッドの実装

`SendClientHello`は、32バイトの乱数と5つの拡張からClientHelloを組み立て、ハンドシェイクのヘッダを付けます。そのうえで、`TLSPlaintext`のレコードに包み、`Conn`の`conn`フィールドが持つTCPの接続に書き込んで送ります。`key_share`拡張には、`GenerateKeyPair`で作った公開鍵を入れます。送ったバイト列は、transcriptに積みます。

::: code-group

```go [handshake_client.go]
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
```

:::

### ServerHelloを受け取って検証するメソッドの実装

`ReadServerHello`は、`Conn`の`readHandshake`でメッセージを1つ取り出し、ServerHelloであることを確かめてからパースします。そのうえで、サーバーが選んだ暗号スイート、バージョン、鍵交換のグループが、クライアントの対応しているものかを確かめます。最後に、サーバーの公開鍵を`serverPublicKey`フィールドに入れ、受け取ったバイト列をtranscriptに積みます。

::: code-group

```go [handshake_client.go]
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
```

:::

### 共有秘密を計算するメソッドを実装する

`ComputeSharedSecret`は、サーバーの公開鍵とクライアントの秘密鍵から、X25519で共有秘密を計算し、`sharedSecret`フィールドに入れます。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) ComputeSharedSecret() error {
	serverPub, err := ecdh.X25519().NewPublicKey(hs.serverPublicKey)
	if err != nil {
		return err
	}
	hs.sharedSecret, err = hs.privateKey.ECDH(serverPub)
	return err
}
```

:::

### handshake traffic secretを導き出すメソッドを実装する

`EstablishHandshakeKeys`は、Key Scheduleに従ってhandshake traffic secretを導き出し、`Conn`をレコードの復号ができる状態に切り替えます。本書で使う鍵の導出処理と`recordProtection`の生成ではエラーを返さないため、このメソッドもエラーを返しません。途中で導き出すHandshake Secretは、後でMain Secretを導出するときにも使うため、`handshakeSecret`フィールドに保存します。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) EstablishHandshakeKeys() {
	hs.handshakeSecret = deriveHandshakeSecret(hs.sharedSecret)
	transcriptHash := hs.transcript.sum()
	hs.clientHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "c hs traffic", transcriptHash)
	hs.serverHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "s hs traffic", transcriptHash)
	hs.c.in = newRecordProtection(hs.serverHandshakeTrafficSecret)
}
```

:::

`hs.c.in = newRecordProtection(hs.serverHandshakeTrafficSecret)`では、サーバーのhandshake traffic secretから作った`recordProtection`を、`Conn`の`in`フィールドに入れます。`in`フィールドに鍵が入った時点から、`Conn`の`readAndDecryptRecord`は届いたレコードを復号するように切り替わります。

### 暗号化されたメッセージを読むメソッドを実装する

ServerHelloのあと、サーバーはEncryptedExtensions、Certificate、CertificateVerifyを順に送ってきます。3つのメッセージを1つずつ読むメソッドを、`ReadEncryptedExtensions`、`ReadCertificate`、`ReadCertificateVerify`として作ります。

証明書や署名の検証は後のページで実装するため、ここではメッセージを取り出して表示するところまで実装します。

::: code-group

```go [handshake_client.go]
func (hs *ClientHandshakeState) ReadEncryptedExtensions() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.HandshakeType != TypeEncryptedExtensions {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", TypeEncryptedExtensions, msg.HandshakeType)
	}
	fmt.Printf("EncryptedExtensions: %d bytes\n", len(msg.Body))
	fmt.Print(hex.Dump(msg.Body))
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
	fmt.Printf("Certificate: %d bytes\n", len(msg.Body))
	fmt.Print(hex.Dump(msg.Body))
	hs.transcript.write(raw)
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

[RFC 9846 §4](https://datatracker.ietf.org/doc/html/rfc9846#section-4)は、決められた順番と違うメッセージを受け取ったらハンドシェイクを中止するよう求めています。そのため、各メソッドは、取り出したメッセージの種別が期待した種別と違えばエラーを返します。

## mainで動かす

`cmd/main.go`で、ここまで実装したメソッドをハンドシェイクの順序に沿って呼び出します。

::: code-group

```go [cmd/main.go]
package main

import (
	"net"

	"tls13"
)

const (
	serverName = "example.com"
	addr       = "example.com:443"
)

func main() {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	hs := tls13.NewClientHandshakeState(conn, serverName)
	if err := hs.GenerateKeyPair(); err != nil {
		panic(err)
	}
	if err := hs.SendClientHello(); err != nil {
		panic(err)
	}
	if err := hs.ReadServerHello(); err != nil {
		panic(err)
	}
	if err := hs.ComputeSharedSecret(); err != nil {
		panic(err)
	}
	hs.EstablishHandshakeKeys()

	if err := hs.ReadEncryptedExtensions(); err != nil {
		panic(err)
	}
	if err := hs.ReadCertificate(); err != nil {
		panic(err)
	}
	if err := hs.ReadCertificateVerify(); err != nil {
		panic(err)
	}
}
```

:::

実行すると、ServerHelloのあとに届いた暗号化レコードが復号され、各ハンドシェイクメッセージの内容が出力されます。

::: details 実行結果

```sh
$ go run ./cmd
EncryptedExtensions: 6 bytes
00000000  00 04 00 00 00 00                                 |......|
Certificate: 3682 bytes
00000000  00 00 0e 5e 00 03 ea 30  82 03 e6 30 82 03 8d a0  |...^...0...0....|
00000010  03 02 01 02 02 10 01 ee  e6 aa bb 52 1d 5e 14 fc  |...........R.^..|
00000020  31 5f d9 98 56 90 30 0a  06 08 2a 86 48 ce 3d 04  |1_..V.0...*.H.=.|
00000030  03 02 30 51 31 0b 30 09  06 03 55 04 06 13 02 55  |..0Q1.0...U....U|
00000040  53 31 18 30 16 06 03 55  04 0a 0c 0f 53 53 4c 20  |S1.0...U....SSL |
00000050  43 6f 72 70 6f 72 61 74  69 6f 6e 31 28 30 26 06  |Corporation1(0&.|
00000060  03 55 04 03 0c 1f 43 6c  6f 75 64 66 6c 61 72 65  |.U....Cloudflare|
00000070  20 54 4c 53 20 49 73 73  75 69 6e 67 20 45 43 43  | TLS Issuing ECC|
00000080  20 43 41 20 33 30 1e 17  0d 32 36 30 39 32 36 32  | CA 30...2609262|
00000090  32 34 39 31 31 5a 17 0d  32 36 31 32 32 35 32 32  |24911Z..26122522|
000000a0  35 36 33 35 5a 30 16 31  14 30 12 06 03 55 04 03  |5635Z0.1.0...U..|
000000b0  0c 0b 65 78 61 6d 70 6c  65 2e 63 6f 6d 30 59 30  |..example.com0Y0|
000000c0  13 06 07 2a 86 48 ce 3d  02 01 06 08 2a 86 48 ce  |...*.H.=....*.H.|
000000d0  3d 03 01 07 03 42 00 04  6a 69 d1 31 5b 3c 53 27  |=....B..ji.1[<S'|
000000e0  84 b7 2d 2c ca 23 30 00  7b 21 74 f6 ad 10 b7 41  |..-,.#0.{!t....A|
000000f0  74 5e 62 e2 66 26 89 48  3d 12 40 f8 55 2b 7e a9  |t^b.f&.H=.@.U+~.|
00000100  50 a9 4c e7 94 d4 b2 d2  67 ad 4e df fb b7 a5 13  |P.L.....g.N.....|
00000110  49 19 11 22 b3 cd c6 ed  a3 82 02 80 30 82 02 7c  |I.."........0..||
00000120  30 0c 06 03 55 1d 13 01  01 ff 04 02 30 00 30 1f  |0...U.......0.0.|
00000130  06 03 55 1d 23 04 18 30  16 80 14 83 03 fd e7 f6  |..U.#..0........|
00000140  f5 4a 4d 15 41 f4 ed 22  16 d3 32 0a 3e ca 66 30  |.JM.A.."..2.>.f0|
00000150  6c 06 08 2b 06 01 05 05  07 01 01 04 60 30 5e 30  |l..+........`0^0|
00000160  39 06 08 2b 06 01 05 05  07 30 02 86 2d 68 74 74  |9..+.....0..-htt|
00000170  70 3a 2f 2f 69 2e 63 66  2d 69 2e 73 73 6c 2e 63  |p://i.cf-i.ssl.c|
00000180  6f 6d 2f 43 6c 6f 75 64  66 6c 61 72 65 2d 54 4c  |om/Cloudflare-TL|
00000190  53 2d 49 2d 45 33 2e 63  65 72 30 21 06 08 2b 06  |S-I-E3.cer0!..+.|
000001a0  01 05 05 07 30 01 86 15  68 74 74 70 3a 2f 2f 6f  |....0...http://o|
000001b0  2e 63 66 2d 69 2e 73 73  6c 2e 63 6f 6d 30 25 06  |.cf-i.ssl.com0%.|
000001c0  03 55 1d 11 04 1e 30 1c  82 0b 65 78 61 6d 70 6c  |.U....0...exampl|
000001d0  65 2e 63 6f 6d 82 0d 2a  2e 65 78 61 6d 70 6c 65  |e.com..*.example|
000001e0  2e 63 6f 6d 30 23 06 03  55 1d 20 04 1c 30 1a 30  |.com0#..U. ..0.0|
000001f0  08 06 06 67 81 0c 01 02  01 30 0e 06 0c 2b 06 01  |...g.....0...+..|
00000200  04 01 82 a9 30 01 03 01  01 30 13 06 03 55 1d 25  |....0....0...U.%|
00000210  04 0c 30 0a 06 08 2b 06  01 05 05 07 03 01 30 53  |..0...+.......0S|
00000220  06 03 55 1d 1f 04 4c 30  4a 30 48 a0 46 a0 44 86  |..U...L0J0H.F.D.|
00000230  42 68 74 74 70 3a 2f 2f  63 2e 63 66 2d 69 2e 73  |Bhttp://c.cf-i.s|
00000240  73 6c 2e 63 6f 6d 2f 61  65 38 30 31 65 64 31 63  |sl.com/ae801ed1c|
00000250  35 35 62 62 35 37 39 64  37 39 32 30 38 62 30 64  |55bb579d79208b0d|
00000260  37 37 32 61 63 66 62 38  63 63 33 61 32 30 38 2e  |772acfb8cc3a208.|
00000270  63 72 6c 30 0e 06 03 55  1d 0f 01 01 ff 04 04 03  |crl0...U........|
00000280  02 07 80 30 0f 06 09 2b  06 01 04 01 82 da 4b 2c  |...0...+......K,|
00000290  04 02 05 00 30 82 01 04  06 0a 2b 06 01 04 01 d6  |....0.....+.....|
000002a0  79 02 04 02 04 81 f5 04  81 f2 00 f0 00 76 00 94  |y............v..|
000002b0  4e 43 87 fa ec c1 ef 81  f3 19 24 26 a8 18 65 01  |NC........$&..e.|
000002c0  c7 d3 5f 38 02 01 3f 72  67 7d 55 37 2e 19 d8 00  |.._8..?rg}U7....|
000002d0  00 01 a0 df f1 ad 62 00  00 04 03 00 47 30 45 02  |......b.....G0E.|
000002e0  21 00 ae 09 46 a1 45 ac  f0 39 ca a3 dc 0e fb cb  |!...F.E..9......|
000002f0  c7 97 75 00 69 2e 51 82  8e ff 43 ff 1b d7 77 75  |..u.i.Q...C...wu|
00000300  fb 84 02 20 6d cd 0a 31  2f 8c b0 03 58 e5 62 c6  |... m..1/...X.b.|
00000310  a4 78 13 93 75 31 93 48  35 55 64 d0 07 bf 2f 61  |.x..u1.H5Ud.../a|
00000320  13 20 6b 51 00 76 00 cb  38 f7 15 89 7c 84 a1 44  |. kQ.v..8...|..D|
00000330  5f 5b c1 dd fb c9 6e f2  9a 59 cd 47 0a 69 05 85  |_[....n..Y.G.i..|
00000340  b0 cb 14 c3 14 58 e7 00  00 01 a0 df f1 ad 7e 00  |.....X........~.|
00000350  00 04 03 00 47 30 45 02  20 1d 98 37 f9 59 3f a7  |....G0E. ..7.Y?.|
00000360  92 04 cb 55 d0 14 eb 18  3e ca 4b 22 95 bb f8 ba  |...U....>.K"....|
00000370  f1 9c da f7 b9 62 f7 a1  5c 02 21 00 d6 6b 6f 4e  |.....b..\.!..koN|
00000380  73 3c cd b3 4a 8f a0 2b  52 95 a6 81 34 54 44 30  |s<..J..+R...4TD0|
00000390  e0 38 2e 11 d4 2d 96 e5  c4 8a e9 f2 30 0a 06 08  |.8...-......0...|
000003a0  2a 86 48 ce 3d 04 03 02  03 47 00 30 44 02 20 34  |*.H.=....G.0D. 4|
000003b0  69 57 c5 62 d3 4e a9 f9  f9 74 0e 90 fd 3a 7d 38  |iW.b.N...t...:}8|
000003c0  1a 11 b8 c3 30 01 d4 20  b9 88 6a 9c 7c 8b 9b 02  |....0.. ..j.|...|
000003d0  20 07 93 23 fc 69 69 f1  99 34 1f 47 c0 d7 c4 79  | ..#.ii..4.G...y|
000003e0  4d 39 ca 1f 9a 4a ff 79  a4 3f 12 36 d2 00 58 da  |M9...J.y.?.6..X.|
000003f0  f4 00 00 00 02 e6 30 82  02 e2 30 82 02 69 a0 03  |......0...0..i..|
00000400  02 01 02 02 10 31 ee e8  8a fb 87 cd 9e f8 33 66  |.....1........3f|
00000410  04 74 3f 9b 27 30 0a 06  08 2a 86 48 ce 3d 04 03  |.t?.'0...*.H.=..|
00000420  03 30 4f 31 0b 30 09 06  03 55 04 06 13 02 55 53  |.0O1.0...U....US|
00000430  31 18 30 16 06 03 55 04  0a 0c 0f 53 53 4c 20 43  |1.0...U....SSL C|
00000440  6f 72 70 6f 72 61 74 69  6f 6e 31 26 30 24 06 03  |orporation1&0$..|
00000450  55 04 03 0c 1d 53 53 4c  2e 63 6f 6d 20 54 4c 53  |U....SSL.com TLS|
00000460  20 54 72 61 6e 73 69 74  20 45 43 43 20 43 41 20  | Transit ECC CA |
00000470  52 32 30 1e 17 0d 32 35  30 35 32 39 31 39 34 39  |R20...2505291949|
00000480  34 35 5a 17 0d 33 35 30  35 32 37 31 39 34 39 34  |45Z..35052719494|
00000490  34 5a 30 51 31 0b 30 09  06 03 55 04 06 13 02 55  |4Z0Q1.0...U....U|
000004a0  53 31 18 30 16 06 03 55  04 0a 0c 0f 53 53 4c 20  |S1.0...U....SSL |
000004b0  43 6f 72 70 6f 72 61 74  69 6f 6e 31 28 30 26 06  |Corporation1(0&.|
000004c0  03 55 04 03 0c 1f 43 6c  6f 75 64 66 6c 61 72 65  |.U....Cloudflare|
000004d0  20 54 4c 53 20 49 73 73  75 69 6e 67 20 45 43 43  | TLS Issuing ECC|
000004e0  20 43 41 20 33 30 59 30  13 06 07 2a 86 48 ce 3d  | CA 30Y0...*.H.=|
000004f0  02 01 06 08 2a 86 48 ce  3d 03 01 07 03 42 00 04  |....*.H.=....B..|
00000500  fd 1d 14 14 8e 23 42 93  26 cf 70 d0 89 d7 b1 1e  |.....#B.&.p.....|
00000510  72 ac 3e 5d 59 52 81 df  1c f5 d6 25 b9 d6 77 07  |r.>]YR.....%..w.|
00000520  85 0b 8d 12 b1 2b 3f 40  b9 1f 72 06 e0 ff 40 52  |.....+?@..r...@R|
00000530  0a 93 49 f8 c9 71 b0 7e  ee e0 a3 45 51 18 44 74  |..I..q.~...EQ.Dt|
00000540  a3 82 01 23 30 82 01 1f  30 12 06 03 55 1d 13 01  |...#0...0...U...|
00000550  01 ff 04 08 30 06 01 01  ff 02 01 00 30 1f 06 03  |....0.......0...|
00000560  55 1d 23 04 18 30 16 80  14 32 a2 c7 d8 58 8b ff  |U.#..0...2...X..|
00000570  7f c0 3c f2 55 69 33 ec  ce cc 1f bc 97 30 48 06  |..<.Ui3......0H.|
00000580  08 2b 06 01 05 05 07 01  01 04 3c 30 3a 30 38 06  |.+........<0:08.|
00000590  08 2b 06 01 05 05 07 30  02 86 2c 68 74 74 70 3a  |.+.....0..,http:|
000005a0  2f 2f 63 65 72 74 2e 73  73 6c 2e 63 6f 6d 2f 53  |//cert.ssl.com/S|
000005b0  53 4c 2e 63 6f 6d 2d 54  4c 53 2d 54 2d 45 43 43  |SL.com-TLS-T-ECC|
000005c0  2d 52 32 2e 63 65 72 30  11 06 03 55 1d 20 04 0a  |-R2.cer0...U. ..|
000005d0  30 08 30 06 06 04 55 1d  20 00 30 1d 06 03 55 1d  |0.0...U. .0...U.|
000005e0  25 04 16 30 14 06 08 2b  06 01 05 05 07 03 02 06  |%..0...+........|
000005f0  08 2b 06 01 05 05 07 03  01 30 3d 06 03 55 1d 1f  |.+.......0=..U..|
00000600  04 36 30 34 30 32 a0 30  a0 2e 86 2c 68 74 74 70  |.60402.0...,http|
00000610  3a 2f 2f 63 72 6c 73 2e  73 73 6c 2e 63 6f 6d 2f  |://crls.ssl.com/|
00000620  53 53 4c 2e 63 6f 6d 2d  54 4c 53 2d 54 2d 45 43  |SSL.com-TLS-T-EC|
00000630  43 2d 52 32 2e 63 72 6c  30 1d 06 03 55 1d 0e 04  |C-R2.crl0...U...|
00000640  16 04 14 83 03 fd e7 f6  f5 4a 4d 15 41 f4 ed 22  |.........JM.A.."|
00000650  16 d3 32 0a 3e ca 66 30  0e 06 03 55 1d 0f 01 01  |..2.>.f0...U....|
00000660  ff 04 04 03 02 01 86 30  0a 06 08 2a 86 48 ce 3d  |.......0...*.H.=|
00000670  04 03 03 03 67 00 30 64  02 30 64 5b f7 60 4c 0a  |....g.0d.0d[.`L.|
00000680  e5 df aa 71 e8 b5 4c 5b  37 c7 2e fd 29 14 3f 8f  |...q..L[7...).?.|
00000690  f4 1a 0e 63 38 ab 67 66  92 d8 8c 2c 40 f1 db d2  |...c8.gf...,@...|
000006a0  b4 1d 64 c6 39 36 08 53  4e 4e 02 30 28 b0 0d 4e  |..d.96.SNN.0(..N|
000006b0  f5 7e 1b 58 55 1b a5 51  ce 7b e4 72 6b a0 b5 e0  |.~.XU..Q.{.rk...|
000006c0  8f e0 64 a6 40 6e 6d d1  e7 6f 6f 9a 3e 90 87 ec  |..d.@nm..oo.>...|
000006d0  b3 fa 40 d4 3f 5e 6f 4d  8a a7 71 03 00 00 00 03  |..@.?^oM..q.....|
000006e0  38 30 82 03 34 30 82 02  b9 a0 03 02 01 02 02 10  |80..40..........|
000006f0  60 4d 8a f8 d0 0b a8 74  8b 95 58 53 17 2c 5f 2e  |`M.....t..XS.,_.|
00000700  30 0a 06 08 2a 86 48 ce  3d 04 03 03 30 4e 31 0b  |0...*.H.=...0N1.|
00000710  30 09 06 03 55 04 06 13  02 55 53 31 18 30 16 06  |0...U....US1.0..|
00000720  03 55 04 0a 0c 0f 53 53  4c 20 43 6f 72 70 6f 72  |.U....SSL Corpor|
00000730  61 74 69 6f 6e 31 25 30  23 06 03 55 04 03 0c 1c  |ation1%0#..U....|
00000740  53 53 4c 2e 63 6f 6d 20  54 4c 53 20 45 43 43 20  |SSL.com TLS ECC |
00000750  52 6f 6f 74 20 43 41 20  32 30 32 32 30 1e 17 0d  |Root CA 20220...|
00000760  32 32 31 30 32 31 31 37  30 32 32 33 5a 17 0d 33  |221021170223Z..3|
00000770  37 31 30 31 37 31 37 30  32 32 32 5a 30 4f 31 0b  |71017170222Z0O1.|
00000780  30 09 06 03 55 04 06 13  02 55 53 31 18 30 16 06  |0...U....US1.0..|
00000790  03 55 04 0a 0c 0f 53 53  4c 20 43 6f 72 70 6f 72  |.U....SSL Corpor|
000007a0  61 74 69 6f 6e 31 26 30  24 06 03 55 04 03 0c 1d  |ation1&0$..U....|
000007b0  53 53 4c 2e 63 6f 6d 20  54 4c 53 20 54 72 61 6e  |SSL.com TLS Tran|
000007c0  73 69 74 20 45 43 43 20  43 41 20 52 32 30 76 30  |sit ECC CA R20v0|
000007d0  10 06 07 2a 86 48 ce 3d  02 01 06 05 2b 81 04 00  |...*.H.=....+...|
000007e0  22 03 62 00 04 64 e7 7d  99 03 53 5c 91 1e ea f8  |".b..d.}..S\....|
000007f0  d8 23 ad a1 bf 2c e2 63  89 ef 28 68 f6 ed d7 f0  |.#...,.c..(h....|
00000800  ec ab 68 ae 77 2b e4 76  97 1b 50 eb db 59 28 2d  |..h.w+.v..P..Y(-|
00000810  6f b8 36 b9 ab 8d 97 ca  4c 22 9e ee 89 d9 02 3f  |o.6.....L".....?|
00000820  fd 7a 73 3a 90 8d 2b cc  2f 3a 37 83 da 0d b4 2d  |.zs:..+./:7....-|
00000830  45 1b 73 72 09 65 5f 78  21 3d e7 8b 66 3f 47 fd  |E.sr.e_x!=..f?G.|
00000840  09 29 d6 14 0f a3 82 01  59 30 82 01 55 30 12 06  |.)......Y0..U0..|
00000850  03 55 1d 13 01 01 ff 04  08 30 06 01 01 ff 02 01  |.U.......0......|
00000860  01 30 1f 06 03 55 1d 23  04 18 30 16 80 14 89 8f  |.0...U.#..0.....|
00000870  2f a3 e8 2b a0 14 54 7b  f3 56 b8 26 5f 67 38 0b  |/..+..T{.V.&_g8.|
00000880  9c d0 30 4c 06 08 2b 06  01 05 05 07 01 01 04 40  |..0L..+........@|
00000890  30 3e 30 3c 06 08 2b 06  01 05 05 07 30 02 86 30  |0>0<..+.....0..0|
000008a0  68 74 74 70 3a 2f 2f 63  65 72 74 2e 73 73 6c 2e  |http://cert.ssl.|
000008b0  63 6f 6d 2f 53 53 4c 63  6f 6d 2d 54 4c 53 2d 52  |com/SSLcom-TLS-R|
000008c0  6f 6f 74 2d 32 30 32 32  2d 45 43 43 2e 63 65 72  |oot-2022-ECC.cer|
000008d0  30 3f 06 03 55 1d 20 04  38 30 36 30 34 06 04 55  |0?..U. .80604..U|
000008e0  1d 20 00 30 2c 30 2a 06  08 2b 06 01 05 05 07 02  |. .0,0*..+......|
000008f0  01 16 1e 68 74 74 70 73  3a 2f 2f 77 77 77 2e 73  |...https://www.s|
00000900  73 6c 2e 63 6f 6d 2f 72  65 70 6f 73 69 74 6f 72  |sl.com/repositor|
00000910  79 30 1d 06 03 55 1d 25  04 16 30 14 06 08 2b 06  |y0...U.%..0...+.|
00000920  01 05 05 07 03 02 06 08  2b 06 01 05 05 07 03 01  |........+.......|
00000930  30 41 06 03 55 1d 1f 04  3a 30 38 30 36 a0 34 a0  |0A..U...:0806.4.|
00000940  32 86 30 68 74 74 70 3a  2f 2f 63 72 6c 73 2e 73  |2.0http://crls.s|
00000950  73 6c 2e 63 6f 6d 2f 53  53 4c 63 6f 6d 2d 54 4c  |sl.com/SSLcom-TL|
00000960  53 2d 52 6f 6f 74 2d 32  30 32 32 2d 45 43 43 2e  |S-Root-2022-ECC.|
00000970  63 72 6c 30 1d 06 03 55  1d 0e 04 16 04 14 32 a2  |crl0...U......2.|
00000980  c7 d8 58 8b ff 7f c0 3c  f2 55 69 33 ec ce cc 1f  |..X....<.Ui3....|
00000990  bc 97 30 0e 06 03 55 1d  0f 01 01 ff 04 04 03 02  |..0...U.........|
000009a0  01 86 30 0a 06 08 2a 86  48 ce 3d 04 03 03 03 69  |..0...*.H.=....i|
000009b0  00 30 66 02 31 00 b8 4a  42 3e 7b 67 2d b3 59 d3  |.0f.1..JB>{g-.Y.|
000009c0  37 d3 02 46 29 7d ef 3e  b6 e1 6c 4b 02 9f 78 85  |7..F)}.>..lK..x.|
000009d0  3e ed 35 91 8f 64 b7 bd  62 22 c8 cb 38 0a a9 6f  |>.5..d..b"..8..o|
000009e0  db 13 46 f6 87 d0 02 31  00 af 57 95 cc 45 cb a7  |..F....1..W..E..|
000009f0  03 29 50 68 24 1c e0 9f  c6 c1 1d 69 ef 2a cf 0b  |.)Ph$......i.*..|
00000a00  40 d1 59 67 b2 2c 09 10  5a 2e 58 96 d6 bd 0f 19  |@.Yg.,..Z.X.....|
00000a10  57 ef 84 05 16 4b 05 08  fd 00 00 00 04 42 30 82  |W....K.......B0.|
00000a20  04 3e 30 82 03 26 a0 03  02 01 02 02 10 17 3d ca  |.>0..&........=.|
00000a30  60 ea 9f 8e 10 26 da fc  d7 28 10 e4 8e 30 0d 06  |`....&...(...0..|
00000a40  09 2a 86 48 86 f7 0d 01  01 0b 05 00 30 7b 31 0b  |.*.H........0{1.|
00000a50  30 09 06 03 55 04 06 13  02 47 42 31 1b 30 19 06  |0...U....GB1.0..|
00000a60  03 55 04 08 0c 12 47 72  65 61 74 65 72 20 4d 61  |.U....Greater Ma|
00000a70  6e 63 68 65 73 74 65 72  31 10 30 0e 06 03 55 04  |nchester1.0...U.|
00000a80  07 0c 07 53 61 6c 66 6f  72 64 31 1a 30 18 06 03  |...Salford1.0...|
00000a90  55 04 0a 0c 11 43 6f 6d  6f 64 6f 20 43 41 20 4c  |U....Comodo CA L|
00000aa0  69 6d 69 74 65 64 31 21  30 1f 06 03 55 04 03 0c  |imited1!0...U...|
00000ab0  18 41 41 41 20 43 65 72  74 69 66 69 63 61 74 65  |.AAA Certificate|
00000ac0  20 53 65 72 76 69 63 65  73 30 1e 17 0d 32 35 30  | Services0...250|
00000ad0  38 30 31 30 30 30 30 30  30 5a 17 0d 32 38 31 32  |801000000Z..2812|
00000ae0  33 31 32 33 35 39 35 39  5a 30 4e 31 0b 30 09 06  |31235959Z0N1.0..|
00000af0  03 55 04 06 13 02 55 53  31 18 30 16 06 03 55 04  |.U....US1.0...U.|
00000b00  0a 0c 0f 53 53 4c 20 43  6f 72 70 6f 72 61 74 69  |...SSL Corporati|
00000b10  6f 6e 31 25 30 23 06 03  55 04 03 0c 1c 53 53 4c  |on1%0#..U....SSL|
00000b20  2e 63 6f 6d 20 54 4c 53  20 45 43 43 20 52 6f 6f  |.com TLS ECC Roo|
00000b30  74 20 43 41 20 32 30 32  32 30 76 30 10 06 07 2a  |t CA 20220v0...*|
00000b40  86 48 ce 3d 02 01 06 05  2b 81 04 00 22 03 62 00  |.H.=....+...".b.|
00000b50  04 45 29 35 73 fa c2 b8  23 ce 14 7d a8 b1 4d a0  |.E)5s...#..}..M.|
00000b60  5b 36 ee 2a 2c 53 c3 60  09 35 b2 24 66 26 69 c0  |[6.*,S.`.5.$f&i.|
00000b70  b3 95 d6 5d 92 40 19 0e  c6 a5 13 70 f4 ef 12 51  |...].@.....p...Q|
00000b80  28 5d e7 cc bd f9 3c 85  c1 cf 94 90 c9 2b ce 92  |(]....<......+..|
00000b90  42 58 59 67 fd 94 27 10  64 8c 4f 04 b1 4d 49 e4  |BXYg..'.d.O..MI.|
00000ba0  7b 4f 9b f5 e7 08 f8 03  88 f7 a7 c3 92 4b 19 54  |{O...........K.T|
00000bb0  81 a3 82 01 97 30 82 01  93 30 1f 06 03 55 1d 23  |.....0...0...U.#|
00000bc0  04 18 30 16 80 14 a0 11  0a 23 3e 96 f1 07 ec e2  |..0......#>.....|
00000bd0  af 29 ef 82 a5 7f d0 30  a4 b4 30 1d 06 03 55 1d  |.).....0..0...U.|
00000be0  0e 04 16 04 14 89 8f 2f  a3 e8 2b a0 14 54 7b f3  |......./..+..T{.|
00000bf0  56 b8 26 5f 67 38 0b 9c  d0 30 0e 06 03 55 1d 0f  |V.&_g8...0...U..|
00000c00  01 01 ff 04 04 03 02 01  86 30 12 06 03 55 1d 13  |.........0...U..|
00000c10  01 01 ff 04 08 30 06 01  01 ff 02 01 02 30 1d 06  |.....0.......0..|
00000c20  03 55 1d 25 04 16 30 14  06 08 2b 06 01 05 05 07  |.U.%..0...+.....|
00000c30  03 01 06 08 2b 06 01 05  05 07 03 02 30 81 92 06  |....+.......0...|
00000c40  03 55 1d 20 04 81 8a 30  81 87 30 07 06 05 67 81  |.U. ...0..0...g.|
00000c50  0c 01 01 30 08 06 06 67  81 0c 01 02 01 30 08 06  |...0...g.....0..|
00000c60  06 67 81 0c 01 02 02 30  08 06 06 67 81 0c 01 02  |.g.....0...g....|
00000c70  03 30 0e 06 0c 2b 06 01  04 01 82 a9 30 01 03 01  |.0...+......0...|
00000c80  01 30 0e 06 0c 2b 06 01  04 01 82 a9 30 01 03 01  |.0...+......0...|
00000c90  02 30 0e 06 0c 2b 06 01  04 01 82 a9 30 01 03 01  |.0...+......0...|
00000ca0  03 30 0e 06 0c 2b 06 01  04 01 82 a9 30 01 03 01  |.0...+......0...|
00000cb0  04 30 0e 06 0c 2b 06 01  04 01 82 a9 30 01 03 01  |.0...+......0...|
00000cc0  05 30 0e 06 0c 2b 06 01  04 01 82 a9 30 01 03 01  |.0...+......0...|
00000cd0  06 30 43 06 03 55 1d 1f  04 3c 30 3a 30 38 a0 36  |.0C..U...<0:08.6|
00000ce0  a0 34 86 32 68 74 74 70  3a 2f 2f 63 72 6c 2e 63  |.4.2http://crl.c|
00000cf0  6f 6d 6f 64 6f 63 61 2e  63 6f 6d 2f 41 41 41 43  |omodoca.com/AAAC|
00000d00  65 72 74 69 66 69 63 61  74 65 53 65 72 76 69 63  |ertificateServic|
00000d10  65 73 2e 63 72 6c 30 34  06 08 2b 06 01 05 05 07  |es.crl04..+.....|
00000d20  01 01 04 28 30 26 30 24  06 08 2b 06 01 05 05 07  |...(0&0$..+.....|
00000d30  30 01 86 18 68 74 74 70  3a 2f 2f 6f 63 73 70 2e  |0...http://ocsp.|
00000d40  63 6f 6d 6f 64 6f 63 61  2e 63 6f 6d 30 0d 06 09  |comodoca.com0...|
00000d50  2a 86 48 86 f7 0d 01 01  0b 05 00 03 82 01 01 00  |*.H.............|
00000d60  43 e5 70 fb 4b ee 24 3c  f0 38 28 86 cb de 46 c3  |C.p.K.$<.8(...F.|
00000d70  2b 2b 9c 60 58 00 57 5b  6b e8 d0 4e 45 d8 be 42  |++.`X.W[k..NE..B|
00000d80  56 1a d2 03 d7 17 f2 52  12 9f f2 d6 6e a7 05 11  |V......R....n...|
00000d90  a6 43 a8 54 1f bd 66 fb  11 d7 90 59 f0 e4 99 ad  |.C.T..f....Y....|
00000da0  1c 3c 52 1d f6 43 3e 9b  61 a9 5e dc f6 7c d2 2c  |.<R..C>.a.^..|.,|
00000db0  c0 86 50 30 49 64 74 3c  3e cc 43 13 14 c5 8f 5b  |..P0Idt<>.C....[|
00000dc0  d8 6b 02 bd 26 fc cf 55  e0 27 17 cc a1 94 91 44  |.k..&..U.'.....D|
00000dd0  24 d5 81 60 e1 b9 ae d6  07 63 01 76 d3 7e 03 cf  |$..`.....c.v.~..|
00000de0  33 a1 77 58 fc f8 55 9e  8c 74 35 96 cc c5 77 42  |3.wX..U..t5...wB|
00000df0  49 67 36 ca 88 d4 10 ed  c0 c1 c1 84 71 32 fd f8  |Ig6.........q2..|
00000e00  8d 70 e8 0f 3d a2 73 50  d1 22 9f 19 7b 3f 5f 3e  |.p..=.sP."..{?_>|
00000e10  94 6a 34 fc 9b 48 07 d4  1b 5d 51 46 ee af 76 81  |.j4..H...]QF..v.|
00000e20  df e9 f4 cc 9f d4 ee ed  f9 0c a8 86 bf 99 a6 34  |...............4|
00000e30  6f 35 95 d6 6b 5a 30 53  27 54 fd 7f 15 48 5a 69  |o5..kZ0S'T...HZi|
00000e40  9b 4d 5c d9 bf 28 0d 32  d5 2e 99 2b 39 0d e9 65  |.M\..(.2...+9..e|
00000e50  8e 19 49 02 27 40 b1 37  3e e6 20 81 26 6a 91 16  |..I.'@.7>. .&j..|
00000e60  00 00                                             |..|
CertificateVerify: 75 bytes
00000000  04 03 00 47 30 45 02 21  00 e2 0a bb 24 ee a8 57  |...G0E.!....$..W|
00000010  6a cf ce 4b 0a 71 9c e8  36 e5 bf 98 ce 7a 5d 9e  |j..K.q..6....z].|
00000020  7e 91 ae 29 bf e2 43 7f  8e 02 20 61 7c 1b 14 06  |~..)..C... a|...|
00000030  38 93 73 24 8b ba 7b e4  ce 45 b8 c8 62 a1 78 4b  |8.s$..{..E..b.xK|
00000040  0e f4 31 28 e6 a9 48 a5  7b 0b 36                 |..1(..H.{.6|
```

:::

## 本ページで書いたコード

::: code-group

```[tree]
.
├── cmd/
│   └── main.go
├── go.mod
├── aead.go
├── bytes.go
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

```go [handshake_client.go]
package tls13

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
)

type ClientHandshakeState struct {
	c          *Conn
	serverName string

	transcript *transcript

	privateKey      *ecdh.PrivateKey
	serverPublicKey []byte
	sharedSecret    []byte

	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
	handshakeSecret              []byte
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
	fmt.Printf("EncryptedExtensions: %d bytes\n", len(msg.Body))
	fmt.Print(hex.Dump(msg.Body))
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
	fmt.Printf("Certificate: %d bytes\n", len(msg.Body))
	fmt.Print(hex.Dump(msg.Body))
	hs.transcript.write(raw)
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

```go [cmd/main.go]
package main

import (
	"net"

	"tls13"
)

const (
	serverName = "example.com"
	addr       = "example.com:443"
)

func main() {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	hs := tls13.NewClientHandshakeState(conn, serverName)
	if err := hs.GenerateKeyPair(); err != nil {
		panic(err)
	}
	if err := hs.SendClientHello(); err != nil {
		panic(err)
	}
	if err := hs.ReadServerHello(); err != nil {
		panic(err)
	}
	if err := hs.ComputeSharedSecret(); err != nil {
		panic(err)
	}
	hs.EstablishHandshakeKeys()

	if err := hs.ReadEncryptedExtensions(); err != nil {
		panic(err)
	}
	if err := hs.ReadCertificate(); err != nil {
		panic(err)
	}
	if err := hs.ReadCertificateVerify(); err != nil {
		panic(err)
	}
}
```

:::
