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
