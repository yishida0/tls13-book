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
