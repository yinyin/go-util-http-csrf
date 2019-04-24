package httpcsrf

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// KeySize is the required size in bytes for encryption key
const KeySize = 32

// ErrKeySizeInsufficient indicates the given key does not have sufficient bytes
var ErrKeySizeInsufficient = errors.New("insufficient bytes for encryption key")

// GenerateKeyString generates a key and pack into string with BASE-64 for encrypting token
func GenerateKeyString() (keyText string, err error) {
	b := make([]byte, KeySize)
	if _, err = rand.Read(b); nil != err {
		return "", err
	}
	keyText = base64.StdEncoding.EncodeToString(b)
	return keyText, nil
}

func unpackKeyString(keyText string) (keyBinary []byte, err error) {
	if keyBinary, err = base64.StdEncoding.DecodeString(keyText); nil != err {
		return
	}
	keyLen := len(keyBinary)
	if keyLen == KeySize {
		return
	} else if keyLen > KeySize {
		return keyBinary[0:KeySize], nil
	}
	return nil, ErrKeySizeInsufficient
}
