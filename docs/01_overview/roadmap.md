# 実装の流れ

## 目指す形

本書では、TLS 1.3クライアントを1つのGoモジュールとして実装します。ルートに`tls13`パッケージを置き、TLSに関する処理をすべてこのパッケージに集約します。

Go標準の`crypto/tls`と同じように、複雑なTLSの処理を意識せず、`Dial`で対象へ接続するだけでTLS接続を確立し、その後は`Write`や`Read`を呼び出すだけで暗号化通信を行えるパッケージを目指します。
`Dial`が返す`Conn`は`io.Writer`と`io.Reader`を満たすので、`fmt.Fprintf`や`io.Copy`にそのまま渡せます。

::: code-group

```go [パッケージ利用時のイメージ]
conn, err := tls13.Dial("tcp", "example.com:443", &tls13.Config{
	ServerName: "example.com",
})
if err != nil {
	return err
}
defer conn.Close()

fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
io.Copy(os.Stdout, conn)
```
:::

完成したライブラリで公開するのは、`Dial`関数と`Config`構造体、`Dial`が返す`Conn`だけです。それ以外の型、関数、定数は、すべて小文字で始まる名前にしてパッケージの中に閉じ込めます。

ただし、本書では実装の途中で`cmd/main.go`から動作を確かめるため、動作確認に使う型や関数、定数だけは一時的に公開します。そのため、途中のコードでは大文字始まりの名前になっているものがあります。一時的に公開したものは、[公開APIを整える](/07_finish/cleanup)のページでまとめて非公開にします。

## 最終的なファイルツリー

完成時のファイルツリーは以下のようになります。

```[tree]
.
├── cmd/
│   └── main.go            tls13パッケージを使ったコードを書く場所
├── go.mod
├── common.go              定数（ContentType、HandshakeType など）
├── bytes.go               バイト列の読み書きヘルパ
├── record.go              TLSPlaintext / TLSCiphertext
├── handshake.go           Handshakeメッセージの共通部分
├── extensions.go          ClientHelloに付ける拡張
├── client_hello.go        ClientHello
├── server_hello.go        ServerHello
├── key_schedule.go        HKDFによる鍵導出
├── aead.go                AES-GCMの初期化
├── record_protection.go   レコードの暗号化と復号
├── certificate.go         Certificate / CertificateVerify とその検証
├── alert.go               Alert
├── handshake_client.go    ハンドシェイクの状態機械
├── conn.go                Conn（レコードとメッセージの読み書き、Write / Read / Close）
└── client.go              Dial
```
