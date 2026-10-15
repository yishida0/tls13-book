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

const maxPayloadLen = 1<<14 + 256

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
