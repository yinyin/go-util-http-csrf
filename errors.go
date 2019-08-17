package httpcsrf

import (
	"errors"
)

// ErrIncompleteEncryptedContent indicate the given encrypted content is smaller than expect.
var ErrIncompleteEncryptedContent = errors.New("incomplete encrypted content")

// ErrCheckSumNotMatch indicate the checksum is not valid.
var ErrCheckSumNotMatch = errors.New("checksum does not match")

// ErrTokenExpired indicate given token is expired.
var ErrTokenExpired = errors.New("token expired")
