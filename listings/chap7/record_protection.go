package tls13

import (
	"crypto/cipher"
	"encoding/binary"
)

type recordProtection struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newRecordProtection(trafficSecret []byte) *recordProtection {
	key, iv := trafficKeys(trafficSecret)
	return &recordProtection{aead: newAESGCM(key), iv: iv}
}

func (p *recordProtection) nextNonce() []byte {
	nonce := make([]byte, len(p.iv))
	copy(nonce, p.iv)
	tail := nonce[len(nonce)-8:]
	binary.BigEndian.PutUint64(tail, binary.BigEndian.Uint64(tail)^p.seq)
	p.seq++
	return nonce
}

func additionalData(contentType contentType, version tlsVersion, length int) []byte {
	return []byte{
		byte(contentType),
		byte(version >> 8), byte(version & 0xff),
		byte(length >> 8), byte(length),
	}
}

func (p *recordProtection) decrypt(rec *tlsPlaintext) (*tlsInnerPlaintext, error) {
	innerBytes, err := p.aead.Open(nil, p.nextNonce(), rec.payload, additionalData(rec.contentType, rec.version, int(rec.length)))
	if err != nil {
		return nil, err
	}
	return parseTLSInnerPlaintext(innerBytes)
}

func (p *recordProtection) encrypt(contentType contentType, plaintext []byte) (encryptedRecord []byte) {
	inner := &tlsInnerPlaintext{content: plaintext, contentType: contentType}
	innerBytes := inner.marshal()
	ciphertextLen := len(innerBytes) + p.aead.Overhead()
	return p.aead.Seal(nil, p.nextNonce(), innerBytes, additionalData(contentTypeApplicationData, tls_version_1_2, ciphertextLen))
}
