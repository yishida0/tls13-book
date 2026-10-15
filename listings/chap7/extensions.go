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
