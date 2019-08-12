package httpcsrf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"time"
)

// DefaultCSRFTokenCookieName is the default name of CSRF cookie if not given.
const DefaultCSRFTokenCookieName = "XSRF-TOKEN"

// DefaultMaxAge is the default max-age for session and CSRF token cookies.
const DefaultMaxAge = time.Hour

// DefaultRenewAge is the default renew age for session and CSRF token cookies.
const DefaultRenewAge = time.Minute * 30

func prependTimestampToBytes(d []byte) (r []byte) {
	r = make([]byte, 8, 8+len(d))
	t := time.Now().Unix()
	binary.LittleEndian.PutUint64(r, uint64(t))
	r = append(r, d...)
	return
}

func extractTimestampFromBytes(d []byte) (t time.Time, b []byte) {
	if len(d) < 8 {
		return
	}
	epochSec := int64(binary.LittleEndian.Uint64(d))
	if epochSec < 0 {
		return
	}
	t = time.Unix(epochSec, 0)
	b = d[8:]
	return
}

// CSRFHelper provide functions to verify CSRF token.
type CSRFHelper struct {
	KeyBinary []byte

	CookiePath   string
	CookieDomain string

	CSRFTokenCookieName string
	MaxCSRFTokenAge     time.Duration
	RenewCSRFTokenAge   time.Duration

	maxCSRFTokenAgeSeconds int
}

// Initialize fill empty fields with default values and prepare internal fields.
func (h *CSRFHelper) Initialize() (err error) {
	if len(h.KeyBinary) != KeySize {
		return ErrKeySizeInsufficient
	}
	if h.CSRFTokenCookieName == "" {
		h.CSRFTokenCookieName = DefaultCSRFTokenCookieName
	}
	if h.MaxCSRFTokenAge < time.Second {
		h.MaxCSRFTokenAge = DefaultMaxAge
	}
	if h.RenewCSRFTokenAge < time.Second {
		h.RenewCSRFTokenAge = DefaultRenewAge
	}
	if h.maxCSRFTokenAgeSeconds = int(h.MaxCSRFTokenAge.Seconds()); h.maxCSRFTokenAgeSeconds < 0 {
		h.maxCSRFTokenAgeSeconds = 1
	}
	return
}

func (h *CSRFHelper) encryptBytes(data []byte) (result string, err error) {
	block, err := aes.NewCipher(h.KeyBinary)
	if nil != err {
		return
	}
	aesgcm, err := cipher.NewGCM(block)
	if nil != err {
		return
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	cipherText := aesgcm.Seal(nil, nonce, data, nil)
	result = base64.RawURLEncoding.EncodeToString(cipherText)
	return
}

func (h *CSRFHelper) makeEncryptedCookie(cookieName string, data []byte, maxAgeSeconds int) (c *http.Cookie, err error) {
	cookieValue, err := h.encryptBytes(data)
	if nil != err {
		return
	}
	c = &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		Path:     h.CookiePath,
		Domain:   h.CookieDomain,
		MaxAge:   maxAgeSeconds,
		SameSite: http.SameSiteStrictMode,
	}
	return
}

// SetCSRFTokenCookie encrypt sessionIdent and set cookie header with given session cookie name.
func (h *CSRFHelper) SetCSRFTokenCookie(w http.ResponseWriter, sessionIdent []byte) (err error) {
	buf := prependTimestampToBytes(sessionIdent)
	cookie, err := h.makeEncryptedCookie(h.CSRFTokenCookieName, buf, h.maxCSRFTokenAgeSeconds)
	if nil != err {
		return
	}
	http.SetCookie(w, cookie)
	return
}
