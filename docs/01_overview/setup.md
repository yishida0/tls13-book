# 環境構築

本書ではGoを使ってTLS 1.3クライアントを実装します。

## Goのインストール

Go 1.25以上が必要です。以下のコマンドでインストールできます。パッケージマネージャーを使わない場合は、[公式のインストール手順](https://go.dev/doc/install)に従ってインストーラを利用します。

::: code-group

```powershell [Windows]
winget install GoLang.Go
```

```sh [macOS]
brew install go
```

```sh [Linux]
curl -LO https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> $HOME/.profile
source $HOME/.profile
```

:::

## バージョン確認

ターミナル（WindowsはPowerShell）で以下を実行し、`go1.25`以上が表示されれば準備完了です。

```sh
$ go version
go version go1.25.0 darwin/arm64
```

## プロジェクトの作成

本書で書くコードはすべて1つのGoモジュールに入れていきます。プロジェクト用のディレクトリを作り、その中で`go mod init`を実行します。

```sh
$ mkdir tls13
$ cd tls13
$ go mod init tls13
go: creating new go.mod: module tls13
```

`go.mod`ができればモジュールの準備は完了です。以降のページに出てくるコマンドは、すべてこのディレクトリの中で実行します。

## コードの整形とimportの整理

本書では、既存のファイルにコードを足す断片から`import`の変更を省くことがあります。Goの拡張機能を使うと、保存時にコードの整形とimportの整理が自動的に行われるため、あらかじめ設定しておくことをおすすめします。

VS Codeを使う場合は、[Go拡張（`golang.go`）](https://marketplace.visualstudio.com/items?itemName=golang.Go)をインストールしてください。ほかのエディタを使用する場合は、Goの公式言語サーバーであるgoplsの[ドキュメント](https://go.dev/gopls/)を参考に、保存時にコードの整形とimportの整理が行われるよう設定してください。

## 動作確認

Goが動くことを確認します。実行ファイルのエントリポイントは`cmd/`ディレクトリに置くので、`cmd/main.go`を作ります。

::: code-group

```go [cmd/main.go]
package main

import "fmt"

func main() {
	fmt.Println("Hello, TLS!")
}
```

:::

プロジェクトのディレクトリで実行します。

```sh
$ go run ./cmd
Hello, TLS!
```

`Hello, TLS!`と表示されれば環境構築は完了です。この時点のディレクトリ構成は次のとおりです。

```[tree]
.
├── cmd/
│   └── main.go
└── go.mod
```
