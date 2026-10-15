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
type NamedGroup uint16

const X25519 NamedGroup = 0x001d

// @see https://datatracker.ietf.org/doc/html/rfc9846#section-4.3.3
type SignatureScheme uint16

const (
	RSA_PKCS1_SHA256       SignatureScheme = 0x0401
	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
	ECDSA_SECP384R1_SHA384 SignatureScheme = 0x0503
	RSA_PSS_RSAE_SHA256    SignatureScheme = 0x0804
	RSA_PSS_RSAE_SHA384    SignatureScheme = 0x0805
	RSA_PSS_RSAE_SHA512    SignatureScheme = 0x0806
)

const maxPayloadLen = 1<<14 + 256
