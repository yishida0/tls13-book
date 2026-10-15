package tls13

type Extension struct {
	Type    extensionType
	Payload []byte
}

func (e Extension) Marshal() []byte {
	buf := appendUint16(nil, uint16(e.Type))
	return append(buf, withUint16Length(e.Payload)...)
}

func UnmarshalExtensions(data []byte) ([]Extension, bool) {
	var exts []Extension
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
		exts = append(exts, Extension{
			Type:    extensionType(extType),
			Payload: append([]byte{}, payload...),
		})
		rest = r
	}
	return exts, true
}

func SupportedVersionsExtension() Extension {
	versions := appendUint16(nil, uint16(TLS_VERSION_1_3))
	return Extension{Type: extSupportedVersions, Payload: withUint8Length(versions)}
}

func ServerNameExtension(name string) Extension {
	entry := append([]byte{0}, withUint16Length([]byte(name))...)
	return Extension{Type: extServerName, Payload: withUint16Length(entry)}
}

func SignatureAlgorithmsExtension() Extension {
	var algorithms []byte
	for _, a := range []SignatureScheme{
		ECDSA_SECP256R1_SHA256, ECDSA_SECP384R1_SHA384,
		RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512,
		RSA_PKCS1_SHA256,
	} {
		algorithms = appendUint16(algorithms, uint16(a))
	}
	return Extension{Type: extSignatureAlgorithms, Payload: withUint16Length(algorithms)}
}

func SupportedGroupsExtension() Extension {
	groups := appendUint16(nil, uint16(X25519))
	return Extension{Type: extSupportedGroups, Payload: withUint16Length(groups)}
}

func KeyShareExtension(publicKey []byte) Extension {
	entry := appendUint16(nil, uint16(X25519))
	entry = append(entry, withUint16Length(publicKey)...)
	return Extension{Type: extKeyShare, Payload: withUint16Length(entry)}
}
