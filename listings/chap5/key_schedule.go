package tls13

import (
	"crypto/hkdf"
	"crypto/sha256"
	"hash"
)

type transcript struct {
	h hash.Hash
}

func newTranscript() *transcript {
	return &transcript{h: sha256.New()}
}

func (t *transcript) write(msg []byte) {
	t.h.Write(msg)
}

func (t *transcript) sum() []byte {
	return t.h.Sum(nil)
}

func hkdfExtract(salt, ikm []byte) []byte {
	secret, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic(err)
	}
	return secret
}

func deriveSecret(secret []byte, label string, transcriptHash []byte) []byte {
	return hkdfExpandLabel(secret, label, transcriptHash, sha256.Size)
}

func deriveEarlySecret() []byte {
	zeros := make([]byte, sha256.Size)
	return hkdfExtract(zeros, zeros)
}

func deriveHandshakeSecret(sharedSecret []byte) []byte {
	emptyHash := sha256.Sum256(nil)
	salt := deriveSecret(deriveEarlySecret(), "derived", emptyHash[:])
	return hkdfExtract(salt, sharedSecret)
}

func deriveMainSecret(handshakeSecret []byte) []byte {
	emptyHash := sha256.Sum256(nil)
	salt := deriveSecret(handshakeSecret, "derived", emptyHash[:])
	return hkdfExtract(salt, make([]byte, sha256.Size))
}

type hkdfLabel struct {
	length  uint16
	label   string
	context []byte
}

func newHkdfLabel(label string, context []byte, length int) *hkdfLabel {
	return &hkdfLabel{
		length:  uint16(length),
		label:   "tls13 " + label,
		context: context,
	}
}

func (l *hkdfLabel) marshal() []byte {
	b := appendUint16(nil, l.length)
	b = append(b, withUint8Length([]byte(l.label))...)
	return append(b, withUint8Length(l.context)...)
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	hkdfLabel := newHkdfLabel(label, context, length)
	out, err := hkdf.Expand(sha256.New, secret, string(hkdfLabel.marshal()), length)
	if err != nil {
		panic(err)
	}
	return out
}

func trafficKeys(secret []byte) (key, iv []byte) {
	key = hkdfExpandLabel(secret, "key", nil, 16)
	iv = hkdfExpandLabel(secret, "iv", nil, 12)
	return key, iv
}
