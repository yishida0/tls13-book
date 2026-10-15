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
