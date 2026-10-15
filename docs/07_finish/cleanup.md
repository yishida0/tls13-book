# 公開APIを整える

本ページでは、不要になったフィールドを削除し、動作確認のために公開していた型、関数、定数を非公開に戻します。パッケージの外から使えるものを`Dial`、`Config`、`Conn`だけにして、TLS 1.3クライアントを完成させます。

## 実装

### 使わなくなったフィールドを削除する

`PeerCertificates`、`VerifiedChains`、`PeerCertificateVerify`は、`cmd/main.go`から証明書や検証結果を表示するために公開していたフィールドです。このうち`VerifiedChains`はほかの処理で使わないため削除し、`VerifyCertificate`で検証結果を保存していた処理も取り除きます。

::: code-group

```go [handshake_client.go]
type ClientHandshakeState struct {
	// ...
	PeerCertificates                []*x509.Certificate
	VerifiedChains                  [][]*x509.Certificate // [!code --]
	PeerCertificateVerify           *CertificateVerify
	certificateVerifyTranscriptHash []byte
}

func (hs *ClientHandshakeState) VerifyCertificate() error {
	certs := hs.PeerCertificates
	// ...
	chains, err := certs[0].Verify(opts) // [!code --]
	if err != nil { // [!code --]
	if _, err := certs[0].Verify(opts); err != nil { // [!code ++]
		return fmt.Errorf("tls13: certificate verification failed: %w", err)
	}
	hs.VerifiedChains = chains // [!code --]
	return nil
}
```

:::

`PeerCertificates`と`PeerCertificateVerify`は、`VerifyCertificateVerify`でサーバー証明書と署名を参照するため残します。

### 型、関数、定数を非公開にする

パッケージの利用者に公開するのは、`Dial`、`Config`、`Conn`だけです。それ以外の型、関数、定数は、名前を小文字で始まるものに変えて非公開にします。

次のコードを`tool/main.go`に書き、プロジェクトのルートで実行すると、変換表`renames`にしたがって名前を変更することができます。

:::: details tool/main.go

::: code-group

```go [tool/main.go]
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type rename struct {
	file string
	old  string
	new  string
}

var renames = []rename{
	{"common.go", "ContentType", "contentType"},
	{"common.go", "ContentTypeChangeCipherSpec", "contentTypeChangeCipherSpec"},
	{"common.go", "ContentTypeAlert", "contentTypeAlert"},
	{"common.go", "ContentTypeHandshake", "contentTypeHandshake"},
	{"common.go", "ContentTypeApplicationData", "contentTypeApplicationData"},
	{"common.go", "HandshakeType", "handshakeType"},
	{"common.go", "TypeClientHello", "typeClientHello"},
	{"common.go", "TypeServerHello", "typeServerHello"},
	{"common.go", "TypeEncryptedExtensions", "typeEncryptedExtensions"},
	{"common.go", "TypeCertificate", "typeCertificate"},
	{"common.go", "TypeCertificateVerify", "typeCertificateVerify"},
	{"common.go", "TypeFinished", "typeFinished"},
	{"common.go", "TLSVersion", "tlsVersion"},
	{"common.go", "TLS_VERSION_1_2", "tls_version_1_2"},
	{"common.go", "TLS_VERSION_1_3", "tls_version_1_3"},
	{"common.go", "CipherSuite", "cipherSuite"},
	{"common.go", "TLS_AES_128_GCM_SHA256", "tls_aes_128_gcm_sha256"},
	{"common.go", "NamedGroup", "namedGroup"},
	{"common.go", "X25519", "x25519"},
	{"common.go", "SignatureScheme", "signatureScheme"},
	{"common.go", "RSA_PKCS1_SHA256", "rsa_pkcs1_sha256"},
	{"common.go", "ECDSA_SECP256R1_SHA256", "ecdsa_secp256r1_sha256"},
	{"common.go", "ECDSA_SECP384R1_SHA384", "ecdsa_secp384r1_sha384"},
	{"common.go", "RSA_PSS_RSAE_SHA256", "rsa_pss_rsae_sha256"},
	{"common.go", "RSA_PSS_RSAE_SHA384", "rsa_pss_rsae_sha384"},
	{"common.go", "RSA_PSS_RSAE_SHA512", "rsa_pss_rsae_sha512"},

	{"record.go", "TLSPlaintext", "tlsPlaintext"},
	{"record.go", "TLSPlaintext.Type", "contentType"},
	{"record.go", "TLSPlaintext.Version", "version"},
	{"record.go", "TLSPlaintext.Length", "length"},
	{"record.go", "TLSPlaintext.Payload", "payload"},
	{"record.go", "TLSPlaintext.Marshal", "marshal"},
	{"record.go", "NewTLSPlaintext", "newTLSPlaintext"},
	{"record.go", "ReadRecord", "readRecord"},

	{"handshake.go", "Handshake", "handshake"},
	{"handshake.go", "Handshake.HandshakeType", "handshakeType"},
	{"handshake.go", "Handshake.Length", "length"},
	{"handshake.go", "Handshake.Body", "body"},
	{"handshake.go", "Handshake.Marshal", "marshal"},
	{"handshake.go", "NewHandshake", "newHandshake"},
	{"handshake.go", "UnmarshalHandshake", "unmarshalHandshake"},

	{"extensions.go", "Extension", "extension"},
	{"extensions.go", "Extension.Type", "extensionType"},
	{"extensions.go", "Extension.Payload", "payload"},
	{"extensions.go", "Extension.Marshal", "marshal"},
	{"extensions.go", "SupportedVersionsExtension", "supportedVersionsExtension"},
	{"extensions.go", "ServerNameExtension", "serverNameExtension"},
	{"extensions.go", "SignatureAlgorithmsExtension", "signatureAlgorithmsExtension"},
	{"extensions.go", "SupportedGroupsExtension", "supportedGroupsExtension"},
	{"extensions.go", "KeyShareExtension", "keyShareExtension"},
	{"extensions.go", "UnmarshalExtensions", "unmarshalExtensions"},

	{"client_hello.go", "ClientHello", "clientHello"},
	{"client_hello.go", "ClientHello.ProtocolVersion", "protocolVersion"},
	{"client_hello.go", "ClientHello.Random", "random"},
	{"client_hello.go", "ClientHello.LegacySessionID", "legacySessionID"},
	{"client_hello.go", "ClientHello.CipherSuites", "cipherSuites"},
	{"client_hello.go", "ClientHello.LegacyCompressionMethods", "legacyCompressionMethods"},
	{"client_hello.go", "ClientHello.Extensions", "extensions"},
	{"client_hello.go", "ClientHello.Marshal", "marshal"},
	{"client_hello.go", "NewClientHello", "newClientHello"},

	{"server_hello.go", "ServerHello", "serverHello"},
	{"server_hello.go", "ServerHello.ProtocolVersion", "protocolVersion"},
	{"server_hello.go", "ServerHello.Random", "random"},
	{"server_hello.go", "ServerHello.LegacySessionID", "legacySessionID"},
	{"server_hello.go", "ServerHello.CipherSuite", "cipherSuite"},
	{"server_hello.go", "ServerHello.CompressionMethod", "compressionMethod"},
	{"server_hello.go", "ServerHello.Extensions", "extensions"},
	{"server_hello.go", "ServerHello.SelectedVersion", "selectedVersion"},
	{"server_hello.go", "ServerHello.KeyShare", "keyShare"},
	{"server_hello.go", "UnmarshalServerHello", "unmarshalServerHello"},

	{"certificate.go", "CertificateVerify", "certificateVerify"},
	{"certificate.go", "CertificateVerify.Algorithm", "algorithm"},
	{"certificate.go", "CertificateVerify.Signature", "signature"},
	{"certificate.go", "CertificateVerify.Verify", "verify"},
	{"certificate.go", "UnmarshalCertificateVerify", "unmarshalCertificateVerify"},

	{"handshake_client.go", "ClientHandshakeState", "clientHandshakeState"},
	{"handshake_client.go", "ClientHandshakeState.PeerCertificates", "peerCertificates"},
	{"handshake_client.go", "ClientHandshakeState.PeerCertificateVerify", "peerCertificateVerify"},
	{"handshake_client.go", "ClientHandshakeState.GenerateKeyPair", "generateKeyPair"},
	{"handshake_client.go", "ClientHandshakeState.SendClientHello", "sendClientHello"},
	{"handshake_client.go", "ClientHandshakeState.ReadServerHello", "readServerHello"},
	{"handshake_client.go", "ClientHandshakeState.ComputeSharedSecret", "computeSharedSecret"},
	{"handshake_client.go", "ClientHandshakeState.EstablishHandshakeKeys", "establishHandshakeKeys"},
	{"handshake_client.go", "ClientHandshakeState.ReadEncryptedExtensions", "readEncryptedExtensions"},
	{"handshake_client.go", "ClientHandshakeState.ReadCertificate", "readCertificate"},
	{"handshake_client.go", "ClientHandshakeState.VerifyCertificate", "verifyCertificate"},
	{"handshake_client.go", "ClientHandshakeState.ReadCertificateVerify", "readCertificateVerify"},
	{"handshake_client.go", "ClientHandshakeState.VerifyCertificateVerify", "verifyCertificateVerify"},
	{"handshake_client.go", "ClientHandshakeState.ReadServerFinished", "readServerFinished"},
	{"handshake_client.go", "ClientHandshakeState.WriteClientFinished", "writeClientFinished"},
	{"handshake_client.go", "ClientHandshakeState.SwitchToApplicationKeys", "switchToApplicationKeys"},
}

type edit struct {
	offset int
	length int
	text   string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (err error) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		return err
	}
	sources := map[string][]byte{}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sources[path] = src
	}

	fset, files, pkg, info, err := check(sources)
	if err != nil {
		return err
	}

	newNames := map[types.Object]string{}
	for _, r := range renames {
		obj, err := lookup(pkg, r.old)
		if err != nil {
			return err
		}
		if got := filepath.Base(fset.Position(obj.Pos()).Filename); got != r.file {
			return fmt.Errorf("%s は %s ではなく %s で定義されています", r.old, r.file, got)
		}
		newNames[obj] = r.new
	}

	edits := map[string][]edit{}
	for path, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			obj := info.Defs[id]
			if obj == nil {
				obj = info.Uses[id]
			}
			if name, ok := newNames[obj]; ok {
				offset := fset.Position(id.Pos()).Offset
				edits[path] = append(edits[path], edit{offset: offset, length: len(id.Name), text: name})
			}
			return true
		})
	}

	results := map[string][]byte{}
	for path, src := range sources {
		out := applyEdits(src, edits[path])
		formatted, err := format.Source(out)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		results[path] = formatted
	}

	if _, _, _, _, err := check(results); err != nil {
		return fmt.Errorf("書き換えたあとのコードがコンパイルできません: %w", err)
	}

	for _, path := range paths {
		if bytes.Equal(results[path], sources[path]) {
			continue
		}
		if err := os.WriteFile(path, results[path], 0o644); err != nil {
			return err
		}
		fmt.Printf("%s: %d か所\n", path, len(edits[path]))
	}
	return nil
}

func check(sources map[string][]byte) (fset *token.FileSet, files map[string]*ast.File, pkg *types.Package, info *types.Info, err error) {
	fset = token.NewFileSet()
	files = map[string]*ast.File{}
	var list []*ast.File
	for path, src := range sources {
		file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		files[path] = file
		list = append(list, file)
	}
	info = &types.Info{
		Defs: map[*ast.Ident]types.Object{},
		Uses: map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err = conf.Check(list[0].Name.Name, fset, list, info)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return fset, files, pkg, info, nil
}

func lookup(pkg *types.Package, name string) (obj types.Object, err error) {
	typeName, member, found := strings.Cut(name, ".")
	obj = pkg.Scope().Lookup(typeName)
	if obj == nil {
		return nil, fmt.Errorf("%s が見つかりません", name)
	}
	if !found {
		return obj, nil
	}
	obj, _, _ = types.LookupFieldOrMethod(obj.Type(), true, pkg, member)
	if obj == nil {
		return nil, fmt.Errorf("%s が見つかりません", name)
	}
	return obj, nil
}

func applyEdits(src []byte, edits []edit) (out []byte) {
	sort.Slice(edits, func(i, j int) bool { return edits[i].offset > edits[j].offset })
	out = append([]byte{}, src...)
	for _, e := range edits {
		out = append(out[:e.offset], append([]byte(e.text), out[e.offset+e.length:]...)...)
	}
	return out
}
```

:::

::::

::: code-group

```sh [ターミナル]
$ go run ./tool
certificate.go: 20 か所
client_hello.go: 32 か所
common.go: 46 か所
conn.go: 33 か所
extensions.go: 48 か所
handshake.go: 25 か所
handshake_client.go: 101 か所
record.go: 34 か所
record_protection.go: 10 か所
server_hello.go: 36 か所
```

:::

`go doc`で、パッケージの外から使える名前を確かめます。

::: code-group

```sh [ターミナル]
$ go doc .
package tls13 // import "tls13"

type Config struct{ ... }
type Conn struct{ ... }
    func Dial(network, addr string, config *Config) (*Conn, error)
```

:::

表示されたのが`Config`、`Conn`、`Dial`だけなので、ほかの型、関数、定数が非公開になったことを確認できます。

## 動かす

外部から見た動作は変わりません。これまでと同じコマンドで実行します。

::: code-group

```sh [ターミナル]
$ go run ./cmd https://example.com/
HTTP/1.1 200 OK
Date: Sat, 03 Oct 2026 15:36:00 GMT
Content-Type: text/html; charset=utf-8
...
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

```go [certificate.go]
package tls13

import (
	"crypto/x509"
	"errors"
	"fmt"
)

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

type certificateVerify struct {
	algorithm signatureScheme
	signature []byte
}

func unmarshalCertificateVerify(body []byte) (*certificateVerify, error) {
	malformed := errors.New("tls13: malformed CertificateVerify")

	algorithm, rest, ok := readUint16(body)
	if !ok {
		return nil, malformed
	}
	signature, rest, ok := readUint16Prefixed(rest)
	if !ok || len(rest) != 0 {
		return nil, malformed
	}
	return &certificateVerify{
		algorithm: signatureScheme(algorithm),
		signature: append([]byte{}, signature...),
	}, nil
}

func (cv *certificateVerify) verify(cert *x509.Certificate, transcriptHash []byte) error {
	content := make([]byte, 0, 64+34+len(transcriptHash))
	for range 64 {
		content = append(content, 0x20)
	}
	content = append(content, "TLS 1.3, server CertificateVerify"...)
	content = append(content, 0)
	content = append(content, transcriptHash...)

	var algorithm x509.SignatureAlgorithm
	switch cv.algorithm {
	case rsa_pss_rsae_sha256:
		algorithm = x509.SHA256WithRSAPSS
	case rsa_pss_rsae_sha384:
		algorithm = x509.SHA384WithRSAPSS
	case rsa_pss_rsae_sha512:
		algorithm = x509.SHA512WithRSAPSS
	case ecdsa_secp256r1_sha256:
		algorithm = x509.ECDSAWithSHA256
	case ecdsa_secp384r1_sha384:
		algorithm = x509.ECDSAWithSHA384
	default:
		return fmt.Errorf("tls13: unsupported signature scheme %#x", uint16(cv.algorithm))
	}
	return cert.CheckSignature(algorithm, content, cv.signature)
}
```

```go [client_hello.go]
package tls13

const clientRandomLength = 32

type clientHello struct {
	protocolVersion          tlsVersion
	random                   [clientRandomLength]byte
	legacySessionID          []byte
	cipherSuites             []cipherSuite
	legacyCompressionMethods []byte
	extensions               []extension
}

func newClientHello(random [clientRandomLength]byte, exts []extension) *clientHello {
	return &clientHello{
		protocolVersion:          tls_version_1_2,
		random:                   random,
		legacySessionID:          nil,
		cipherSuites:             []cipherSuite{tls_aes_128_gcm_sha256},
		legacyCompressionMethods: []byte{0x00},
		extensions:               exts,
	}
}

func (ch *clientHello) marshal() []byte {
	var cipherSuites []byte
	for _, cs := range ch.cipherSuites {
		cipherSuites = appendUint16(cipherSuites, uint16(cs))
	}

	var extensions []byte
	for _, ext := range ch.extensions {
		extensions = append(extensions, ext.marshal()...)
	}

	buf := appendUint16(nil, uint16(ch.protocolVersion))
	buf = append(buf, ch.random[:]...)
	buf = append(buf, withUint8Length(ch.legacySessionID)...)
	buf = append(buf, withUint16Length(cipherSuites)...)
	buf = append(buf, withUint8Length(ch.legacyCompressionMethods)...)
	return append(buf, withUint16Length(extensions)...)
}
```

```go [common.go]
package tls13

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-5.1
type contentType uint8

const (
	contentTypeChangeCipherSpec contentType = 20
	contentTypeAlert            contentType = 21
	contentTypeHandshake        contentType = 22
	contentTypeApplicationData  contentType = 23
)

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4.2.2
type tlsVersion uint16

const (
	tls_version_1_2 tlsVersion = 0x0303
	tls_version_1_3 tlsVersion = 0x0304
)

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4
type handshakeType uint8

const (
	typeClientHello         handshakeType = 1
	typeServerHello         handshakeType = 2
	typeEncryptedExtensions handshakeType = 8
	typeCertificate         handshakeType = 11
	typeCertificateVerify   handshakeType = 15
	typeFinished            handshakeType = 20
)

// @see https://datatracker.ietf.org/doc/html/rfc9846#appendix-B.4
type cipherSuite uint16

const tls_aes_128_gcm_sha256 cipherSuite = 0x1301

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
type namedGroup uint16

const x25519 namedGroup = 0x001d

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.3
type signatureScheme uint16

const (
	rsa_pkcs1_sha256       signatureScheme = 0x0401
	ecdsa_secp256r1_sha256 signatureScheme = 0x0403
	ecdsa_secp384r1_sha384 signatureScheme = 0x0503
	rsa_pss_rsae_sha256    signatureScheme = 0x0804
	rsa_pss_rsae_sha384    signatureScheme = 0x0805
	rsa_pss_rsae_sha512    signatureScheme = 0x0806
)

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-6
type alertDescription uint8

const closeNotify alertDescription = 0

const alertLevelWarning = 1

const maxPlaintextLen = 1 << 14

const maxPayloadLen = 1<<14 + 256
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
		if err := c.writeRecord(newTLSPlaintext(contentTypeApplicationData, p[n:end])); err != nil {
			return n, err
		}
		n = end
	}
	return n, nil
}

func (c *Conn) Close() error {
	if c.out != nil {
		alert := &alert{level: alertLevelWarning, description: closeNotify}
		c.writeRecord(newTLSPlaintext(contentTypeAlert, alert.marshal()))
	}
	return c.conn.Close()
}

func (c *Conn) Read(p []byte) (n int, err error) {
	for len(c.appDataBuf) == 0 {
		rec, err := c.readAndDecryptRecord()
		if err != nil {
			return 0, err
		}
		switch rec.contentType {
		case contentTypeApplicationData:
			c.appDataBuf = rec.payload
		case contentTypeHandshake:
		case contentTypeAlert:
			return 0, c.alertError(rec.payload)
		default:
			return 0, fmt.Errorf("tls13: unexpected record type %d", rec.contentType)
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

func (c *Conn) readAndDecryptRecord() (rec *tlsPlaintext, err error) {
	for {
		rec, err = readRecord(c.conn)
		if err != nil {
			return nil, err
		}
		if rec.contentType != contentTypeChangeCipherSpec {
			break
		}
	}
	if c.in == nil {
		return rec, nil
	}
	if rec.contentType != contentTypeApplicationData {
		return nil, fmt.Errorf("tls13: unexpected plaintext record type %d", rec.contentType)
	}
	inner, err := c.in.decrypt(rec)
	if err != nil {
		return nil, err
	}
	return newTLSPlaintext(inner.contentType, inner.content), nil
}

func (c *Conn) readHandshake() (msg *handshake, raw []byte, err error) {
	for !hasCompleteHandshake(c.handshakeBuf) {
		rec, err := c.readAndDecryptRecord()
		if err != nil {
			return nil, nil, err
		}
		switch rec.contentType {
		case contentTypeHandshake:
			c.handshakeBuf = append(c.handshakeBuf, rec.payload...)
		case contentTypeAlert:
			return nil, nil, fmt.Errorf("tls13: received alert record: % x", rec.payload)
		default:
			return nil, nil, fmt.Errorf("tls13: unexpected record type %d during handshake", rec.contentType)
		}
	}
	n := 4 + handshakeBodyLen(c.handshakeBuf)
	raw = c.handshakeBuf[:n]
	c.handshakeBuf = c.handshakeBuf[n:]
	msg, err = unmarshalHandshake(raw)
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

func (c *Conn) writeRecord(rec *tlsPlaintext) (err error) {
	if c.out != nil {
		rec = newTLSPlaintext(contentTypeApplicationData, c.out.encrypt(rec.contentType, rec.payload))
	}
	_, err = c.conn.Write(rec.marshal())
	return err
}
```

```go [extensions.go]
package tls13

type extension struct {
	extensionType extensionType
	payload       []byte
}

func (e extension) marshal() []byte {
	buf := appendUint16(nil, uint16(e.extensionType))
	return append(buf, withUint16Length(e.payload)...)
}

func unmarshalExtensions(data []byte) ([]extension, bool) {
	var exts []extension
	rest := data
	for len(rest) > 0 {
		extType, r, ok := readUint16(rest)
		if !ok {
			return nil, false
		}
		payload, r, ok := readUint16Prefixed(r)
		if !ok {
			return nil, false
		}
		exts = append(exts, extension{
			extensionType: extensionType(extType),
			payload:       append([]byte{}, payload...),
		})
		rest = r
	}
	return exts, true
}

func supportedVersionsExtension() extension {
	versions := appendUint16(nil, uint16(tls_version_1_3))
	return extension{extensionType: extSupportedVersions, payload: withUint8Length(versions)}
}

func serverNameExtension(name string) extension {
	entry := append([]byte{0}, withUint16Length([]byte(name))...)
	return extension{extensionType: extServerName, payload: withUint16Length(entry)}
}

func signatureAlgorithmsExtension() extension {
	var algorithms []byte
	for _, a := range []signatureScheme{
		ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
		rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512,
		rsa_pkcs1_sha256,
	} {
		algorithms = appendUint16(algorithms, uint16(a))
	}
	return extension{extensionType: extSignatureAlgorithms, payload: withUint16Length(algorithms)}
}

func supportedGroupsExtension() extension {
	groups := appendUint16(nil, uint16(x25519))
	return extension{extensionType: extSupportedGroups, payload: withUint16Length(groups)}
}

func keyShareExtension(publicKey []byte) extension {
	entry := appendUint16(nil, uint16(x25519))
	entry = append(entry, withUint16Length(publicKey)...)
	return extension{extensionType: extKeyShare, payload: withUint16Length(entry)}
}
```

```go [handshake.go]
package tls13

import "errors"

var errHandshakeTooShort = errors.New("tls13: handshake message too short")

type handshake struct {
	handshakeType handshakeType
	length        [3]byte
	body          []byte
}

func newHandshake(handshakeType handshakeType, body []byte) *handshake {
	length := len(body)
	return &handshake{
		handshakeType: handshakeType,
		length:        [3]byte{byte(length >> 16), byte(length >> 8), byte(length)},
		body:          body,
	}
}

func (h *handshake) marshal() []byte {
	buf := make([]byte, 4, 4+len(h.body))
	buf[0] = byte(h.handshakeType)
	copy(buf[1:], h.length[:])
	return append(buf, h.body...)
}

func unmarshalHandshake(data []byte) (*handshake, error) {
	if len(data) < 4 {
		return nil, errHandshakeTooShort
	}
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) != 4+length {
		return nil, errors.New("tls13: handshake length mismatch")
	}
	return &handshake{
		handshakeType: handshakeType(data[0]),
		length:        [3]byte{data[1], data[2], data[3]},
		body:          data[4:],
	}, nil
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

type clientHandshakeState struct {
	c *Conn

	transcript *transcript

	privateKey      *ecdh.PrivateKey
	serverPublicKey []byte
	sharedSecret    []byte

	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
	handshakeSecret              []byte

	peerCertificates                []*x509.Certificate
	peerCertificateVerify           *certificateVerify
	certificateVerifyTranscriptHash []byte
}

func (c *Conn) handshake() error {
	hs := &clientHandshakeState{
		c:          c,
		transcript: newTranscript(),
	}
	if err := hs.generateKeyPair(); err != nil {
		return err
	}
	if err := hs.sendClientHello(); err != nil {
		return err
	}
	if err := hs.readServerHello(); err != nil {
		return err
	}
	if err := hs.computeSharedSecret(); err != nil {
		return err
	}
	hs.establishHandshakeKeys()
	if err := hs.readEncryptedExtensions(); err != nil {
		return err
	}
	if err := hs.readCertificate(); err != nil {
		return err
	}
	if err := hs.verifyCertificate(); err != nil {
		return err
	}
	if err := hs.readCertificateVerify(); err != nil {
		return err
	}
	if err := hs.verifyCertificateVerify(); err != nil {
		return err
	}
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	if err := hs.writeClientFinished(); err != nil {
		return err
	}
	hs.switchToApplicationKeys()
	return nil
}

func (hs *clientHandshakeState) generateKeyPair() error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	hs.privateKey = privateKey
	return nil
}

func (hs *clientHandshakeState) sendClientHello() error {
	var random [clientRandomLength]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}

	ch := newClientHello(random, []extension{
		supportedVersionsExtension(),
		serverNameExtension(hs.c.config.ServerName),
		signatureAlgorithmsExtension(),
		supportedGroupsExtension(),
		keyShareExtension(hs.privateKey.PublicKey().Bytes()),
	})
	h := newHandshake(typeClientHello, ch.marshal())
	raw := h.marshal()
	if err := hs.c.writeRecord(newTLSPlaintext(contentTypeHandshake, raw)); err != nil {
		return err
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) readServerHello() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeServerHello {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeServerHello, msg.handshakeType)
	}
	sh, err := unmarshalServerHello(msg.body)
	if err != nil {
		return err
	}
	if sh.cipherSuite != tls_aes_128_gcm_sha256 {
		return fmt.Errorf("tls13: server selected unsupported cipher suite %#x", uint16(sh.cipherSuite))
	}
	if v, ok := sh.selectedVersion(); !ok || v != tls_version_1_3 {
		return errors.New("tls13: server did not negotiate TLS 1.3")
	}
	group, serverPublicKey, ok := sh.keyShare()
	if !ok {
		return errors.New("tls13: server did not send a key share")
	}
	if group != x25519 {
		return fmt.Errorf("tls13: server selected unsupported group %#x", uint16(group))
	}
	hs.serverPublicKey = serverPublicKey
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) computeSharedSecret() error {
	serverPub, err := ecdh.X25519().NewPublicKey(hs.serverPublicKey)
	if err != nil {
		return err
	}
	hs.sharedSecret, err = hs.privateKey.ECDH(serverPub)
	return err
}

func (hs *clientHandshakeState) establishHandshakeKeys() {
	hs.handshakeSecret = deriveHandshakeSecret(hs.sharedSecret)
	transcriptHash := hs.transcript.sum()
	hs.clientHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "c hs traffic", transcriptHash)
	hs.serverHandshakeTrafficSecret = deriveSecret(hs.handshakeSecret, "s hs traffic", transcriptHash)
	hs.c.in = newRecordProtection(hs.serverHandshakeTrafficSecret)
}

func (hs *clientHandshakeState) readEncryptedExtensions() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeEncryptedExtensions {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeEncryptedExtensions, msg.handshakeType)
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) readCertificate() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeCertificate {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeCertificate, msg.handshakeType)
	}
	certificate, err := unmarshalCertificate(msg.body)
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
	hs.peerCertificates = certs
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) verifyCertificate() error {
	certs := hs.peerCertificates
	opts := x509.VerifyOptions{
		DNSName:       hs.c.config.ServerName,
		Roots:         hs.c.config.RootCAs,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("tls13: certificate verification failed: %w", err)
	}
	return nil
}

func (hs *clientHandshakeState) readCertificateVerify() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeCertificateVerify {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeCertificateVerify, msg.handshakeType)
	}
	cv, err := unmarshalCertificateVerify(msg.body)
	if err != nil {
		return err
	}
	hs.peerCertificateVerify = cv
	hs.certificateVerifyTranscriptHash = hs.transcript.sum()
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) verifyCertificateVerify() error {
	return hs.peerCertificateVerify.verify(hs.peerCertificates[0], hs.certificateVerifyTranscriptHash)
}

func (hs *clientHandshakeState) readServerFinished() error {
	msg, raw, err := hs.c.readHandshake()
	if err != nil {
		return err
	}
	if msg.handshakeType != typeFinished {
		return fmt.Errorf("tls13: expected handshake message %d, got %d", typeFinished, msg.handshakeType)
	}
	want := finishedVerifyData(hs.serverHandshakeTrafficSecret, hs.transcript.sum())
	if !hmac.Equal(msg.body, want) {
		return errors.New("tls13: invalid server Finished")
	}
	hs.transcript.write(raw)
	return nil
}

func (hs *clientHandshakeState) writeClientFinished() error {
	msg := newHandshake(typeFinished, finishedVerifyData(hs.clientHandshakeTrafficSecret, hs.transcript.sum()))
	hs.c.out = newRecordProtection(hs.clientHandshakeTrafficSecret)
	return hs.c.writeRecord(newTLSPlaintext(contentTypeHandshake, msg.marshal()))
}

func (hs *clientHandshakeState) switchToApplicationKeys() {
	mainSecret := deriveMainSecret(hs.handshakeSecret)
	transcriptHash := hs.transcript.sum()
	hs.c.in = newRecordProtection(deriveSecret(mainSecret, "s ap traffic", transcriptHash))
	hs.c.out = newRecordProtection(deriveSecret(mainSecret, "c ap traffic", transcriptHash))
}
```

```go [record.go]
package tls13

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	errPayloadTooLarge      = errors.New("tls13: payload too large")
	errInnerPlaintextNoType = errors.New("tls13: inner plaintext missing content type")
)

type tlsPlaintext struct {
	contentType contentType
	version     tlsVersion
	length      uint16
	payload     []byte
}

func newTLSPlaintext(contentType contentType, fragment []byte) *tlsPlaintext {
	return &tlsPlaintext{
		contentType: contentType,
		version:     tls_version_1_2,
		length:      uint16(len(fragment)),
		payload:     fragment,
	}
}

func (p *tlsPlaintext) marshal() []byte {
	buf := make([]byte, 5, 5+len(p.payload))
	buf[0] = byte(p.contentType)
	binary.BigEndian.PutUint16(buf[1:], uint16(p.version))
	binary.BigEndian.PutUint16(buf[3:], p.length)
	return append(buf, p.payload...)
}

func readRecord(r io.Reader) (*tlsPlaintext, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(hdr[3:])
	if int(length) > maxPayloadLen {
		return nil, errPayloadTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &tlsPlaintext{
		contentType: contentType(hdr[0]),
		version:     tlsVersion(binary.BigEndian.Uint16(hdr[1:])),
		length:      length,
		payload:     payload,
	}, nil
}

type tlsInnerPlaintext struct {
	content     []byte
	contentType contentType
}

func (p *tlsInnerPlaintext) marshal() []byte {
	buf := make([]byte, 0, len(p.content)+1)
	buf = append(buf, p.content...)
	return append(buf, byte(p.contentType))
}

func parseTLSInnerPlaintext(data []byte) (*tlsInnerPlaintext, error) {
	i := len(data) - 1
	for i >= 0 && data[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, errInnerPlaintextNoType
	}
	return &tlsInnerPlaintext{
		content:     data[:i],
		contentType: contentType(data[i]),
	}, nil
}
```

```go [record_protection.go]
package tls13

import (
	"crypto/cipher"
	"encoding/binary"
)

type recordProtection struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newRecordProtection(trafficSecret []byte) *recordProtection {
	key, iv := trafficKeys(trafficSecret)
	return &recordProtection{aead: newAESGCM(key), iv: iv}
}

func (p *recordProtection) nextNonce() []byte {
	nonce := make([]byte, len(p.iv))
	copy(nonce, p.iv)
	tail := nonce[len(nonce)-8:]
	binary.BigEndian.PutUint64(tail, binary.BigEndian.Uint64(tail)^p.seq)
	p.seq++
	return nonce
}

func additionalData(contentType contentType, version tlsVersion, length int) []byte {
	return []byte{
		byte(contentType),
		byte(version >> 8), byte(version & 0xff),
		byte(length >> 8), byte(length),
	}
}

func (p *recordProtection) decrypt(rec *tlsPlaintext) (*tlsInnerPlaintext, error) {
	innerBytes, err := p.aead.Open(nil, p.nextNonce(), rec.payload, additionalData(rec.contentType, rec.version, int(rec.length)))
	if err != nil {
		return nil, err
	}
	return parseTLSInnerPlaintext(innerBytes)
}

func (p *recordProtection) encrypt(contentType contentType, plaintext []byte) (encryptedRecord []byte) {
	inner := &tlsInnerPlaintext{content: plaintext, contentType: contentType}
	innerBytes := inner.marshal()
	ciphertextLen := len(innerBytes) + p.aead.Overhead()
	return p.aead.Seal(nil, p.nextNonce(), innerBytes, additionalData(contentTypeApplicationData, tls_version_1_2, ciphertextLen))
}
```

```go [server_hello.go]
package tls13

import "errors"

type serverHello struct {
	protocolVersion   tlsVersion
	random            [32]byte
	legacySessionID   []byte
	cipherSuite       cipherSuite
	compressionMethod uint8
	extensions        []extension
}

func unmarshalServerHello(body []byte) (*serverHello, error) {
	malformed := errors.New("tls13: malformed ServerHello")

	version, rest, ok := readUint16(body)
	if !ok {
		return nil, malformed
	}
	random, rest, ok := readBytes(rest, 32)
	if !ok {
		return nil, malformed
	}
	sessionID, rest, ok := readUint8Prefixed(rest)
	if !ok {
		return nil, malformed
	}
	suite, rest, ok := readUint16(rest)
	if !ok {
		return nil, malformed
	}
	compressionMethod, rest, ok := readUint8(rest)
	if !ok {
		return nil, malformed
	}
	extensions, rest, ok := readUint16Prefixed(rest)
	if !ok || len(rest) != 0 {
		return nil, malformed
	}

	exts, ok := unmarshalExtensions(extensions)
	if !ok {
		return nil, errors.New("tls13: malformed ServerHello extensions")
	}

	sh := &serverHello{
		protocolVersion:   tlsVersion(version),
		legacySessionID:   append([]byte{}, sessionID...),
		cipherSuite:       cipherSuite(suite),
		compressionMethod: compressionMethod,
		extensions:        exts,
	}
	copy(sh.random[:], random)
	return sh, nil
}

func (sh *serverHello) selectedVersion() (version tlsVersion, found bool) {
	for _, ext := range sh.extensions {
		if ext.extensionType == extSupportedVersions {
			if v, _, ok := readUint16(ext.payload); ok {
				return tlsVersion(v), true
			}
		}
	}
	return 0, false
}

func (sh *serverHello) keyShare() (group namedGroup, publicKey []byte, found bool) {
	for _, ext := range sh.extensions {
		if ext.extensionType == extKeyShare {
			g, rest, ok := readUint16(ext.payload)
			if !ok {
				continue
			}
			key, _, ok := readUint16Prefixed(rest)
			if !ok {
				continue
			}
			return namedGroup(g), key, true
		}
	}
	return 0, nil, false
}
```

:::
