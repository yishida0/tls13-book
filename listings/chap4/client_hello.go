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
