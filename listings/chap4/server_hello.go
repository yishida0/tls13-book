package tls13

import "errors"

type ServerHello struct {
	ProtocolVersion   TLSVersion
	Random            [32]byte
	LegacySessionID   []byte
	CipherSuite       CipherSuite
	CompressionMethod uint8
	Extensions        []Extension
}

func UnmarshalServerHello(body []byte) (*ServerHello, error) {
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

	exts, ok := UnmarshalExtensions(extensions)
	if !ok {
		return nil, errors.New("tls13: malformed ServerHello extensions")
	}

	sh := &ServerHello{
		ProtocolVersion:   TLSVersion(version),
		LegacySessionID:   append([]byte{}, sessionID...),
		CipherSuite:       CipherSuite(suite),
		CompressionMethod: compressionMethod,
		Extensions:        exts,
	}
	copy(sh.Random[:], random)
	return sh, nil
}

func (sh *ServerHello) SelectedVersion() (version TLSVersion, found bool) {
	for _, ext := range sh.Extensions {
		if ext.Type == extSupportedVersions {
			if v, _, ok := readUint16(ext.Payload); ok {
				return TLSVersion(v), true
			}
		}
	}
	return 0, false
}

func (sh *ServerHello) KeyShare() (group NamedGroup, publicKey []byte, found bool) {
	for _, ext := range sh.Extensions {
		if ext.Type == extKeyShare {
			g, rest, ok := readUint16(ext.Payload)
			if !ok {
				continue
			}
			key, _, ok := readUint16Prefixed(rest)
			if !ok {
				continue
			}
			return NamedGroup(g), key, true
		}
	}
	return 0, nil, false
}
