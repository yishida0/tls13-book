package tls13

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func withUint8Length(body []byte) []byte {
	return append([]byte{byte(len(body))}, body...)
}

func withUint16Length(body []byte) []byte {
	return append([]byte{byte(len(body) >> 8), byte(len(body))}, body...)
}

func readUint8(b []byte) (value uint8, rest []byte, ok bool) {
	if len(b) < 1 {
		return 0, nil, false
	}
	return b[0], b[1:], true
}

func readUint16(b []byte) (value uint16, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, false
	}
	return uint16(b[0])<<8 | uint16(b[1]), b[2:], true
}

func readBytes(b []byte, n int) (value []byte, rest []byte, ok bool) {
	if len(b) < n {
		return nil, nil, false
	}
	return b[:n], b[n:], true
}

func readUint8Prefixed(b []byte) (value []byte, rest []byte, ok bool) {
	n, rest, ok := readUint8(b)
	if !ok {
		return nil, nil, false
	}
	return readBytes(rest, int(n))
}

func readUint16Prefixed(b []byte) (value []byte, rest []byte, ok bool) {
	n, rest, ok := readUint16(b)
	if !ok {
		return nil, nil, false
	}
	return readBytes(rest, int(n))
}

func readUint24Prefixed(b []byte) (value []byte, rest []byte, ok bool) {
	if len(b) < 3 {
		return nil, nil, false
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return readBytes(b[3:], n)
}
