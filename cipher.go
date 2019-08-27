package httpcsrf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"hash/adler32"
	"io"
)

// CipherHelper provide functions to encrypt and decrypt bytes.
type CipherHelper struct {
	KeyBinary []byte
	HashMask  uint32
}

func (h *CipherHelper) prepareAEAD() (aead cipher.AEAD, err error) {
	block, err := aes.NewCipher(h.KeyBinary)
	if nil != err {
		return
	}
	return cipher.NewGCM(block)
}

// EncryptBytesToString encrypt given data bytes and encode encrypted binary to
// string with given base64Encoding.
func (h *CipherHelper) EncryptBytesToString(data []byte, base64Encoding *base64.Encoding) (result string, err error) {
	if len(data) == 0 {
		return
	}
	aead, err := h.prepareAEAD()
	if nil != err {
		return
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	cipherText := aead.Seal(nil, nonce, data, nil)
	cipherText = append(cipherText, nonce...)
	checksum32 := adler32.Checksum(cipherText)
	checksum32 = checksum32 ^ h.HashMask
	chkbuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(chkbuf, checksum32)
	cipherText = append(cipherText, chkbuf...)
	result = base64Encoding.EncodeToString(cipherText)
	return
}

// EncryptBytes encrypt given data bytes and enode encrypted binary to string
// with base64.RawURLEncoding.
func (h *CipherHelper) EncryptBytes(data []byte) (result string, err error) {
	return h.EncryptBytesToString(data, base64.RawURLEncoding)
}

// DecryptStringToBytes decode given encryptedString with given base64Encoding
// and decrypt result binary to bytes.
func (h *CipherHelper) DecryptStringToBytes(encryptedString string, base64Encoding *base64.Encoding) (result []byte, err error) {
	cipherText, err := base64Encoding.DecodeString(encryptedString)
	if nil != err {
		return
	}
	if len(cipherText) < 4 {
		return nil, ErrIncompleteEncryptedContent
	}
	checksum32 := binary.LittleEndian.Uint32(cipherText[len(cipherText)-4:])
	checksum32 = checksum32 ^ h.HashMask
	cipherText = cipherText[:len(cipherText)-4]
	if adler32.Checksum(cipherText) != checksum32 {
		return nil, ErrCheckSumNotMatch
	}
	aead, err := h.prepareAEAD()
	if nil != err {
		return
	}
	nonceSize := aead.NonceSize()
	nonceBound := len(cipherText) - nonceSize
	if nonceBound < 0 {
		return nil, ErrIncompleteEncryptedContent
	}
	nonce := cipherText[nonceBound:]
	cipherText = cipherText[:nonceBound]
	return aead.Open(nil, nonce, cipherText, nil)
}

// DecryptString decode given encryptedString with base64.RawURLEncoding and
// decrypt result binary to bytes.
func (h *CipherHelper) DecryptString(encryptedString string) (result []byte, err error) {
	return h.DecryptStringToBytes(encryptedString, base64.RawURLEncoding)
}
