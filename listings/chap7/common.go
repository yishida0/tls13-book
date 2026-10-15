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
