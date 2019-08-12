package httpcsrf

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// KeySize is the required size in bytes for encryption key.
const KeySize = 32

// ErrKeySizeInsufficient indicates the given key does not have sufficient bytes.
var ErrKeySizeInsufficient = errors.New("insufficient bytes for encryption key")

// GenerateKey generate a key with required key size.
func GenerateKey() (keyBinary []byte, err error) {
	keyBinary = make([]byte, KeySize)
	if _, err = rand.Read(keyBinary); nil != err {
		return nil, err
	}
	return
}

// PackKeyToString encode given key binary into string with BASE-64 encoding.
func PackKeyToString(keyBinary []byte) (keyText string) {
	keyText = base64.RawStdEncoding.EncodeToString(keyBinary)
	return
}

// UnpackKeyFromString decode given key binary from string in BASE-64 encoding.
func UnpackKeyFromString(keyText string) (keyBinary []byte, err error) {
	if keyBinary, err = base64.RawStdEncoding.DecodeString(keyText); nil != err {
		return
	}
	if keyLen := len(keyBinary); keyLen == KeySize {
		return
	} else if keyLen > KeySize {
		return keyBinary[0:KeySize], nil
	}
	return nil, ErrKeySizeInsufficient
}
