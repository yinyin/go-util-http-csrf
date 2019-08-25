package httpcsrf

import (
	"encoding/binary"
	"net/http"
	"time"
)

// DefaultCSRFTokenCookieName is the default name of CSRF cookie if not given.
const DefaultCSRFTokenCookieName = "XSRF-TOKEN"

// DefaultCSRFTokenHeaderName is the default name of CSRF header if not given.
const DefaultCSRFTokenHeaderName = "X-XSRF-TOKEN"

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

func timestampFromPrependBytes(b []byte) (t time.Time, d []byte) {
	if len(b) < 8 {
		return
	}
	epochSec := int64(binary.LittleEndian.Uint64(b))
	if epochSec < 0 {
		return
	}
	t = time.Unix(epochSec, 0)
	d = b[8:]
	return
}

// CSRFHelper provide functions to verify CSRF token.
type CSRFHelper struct {
	CipherHelper

	CookiePath   string
	CookieDomain string

	CSRFTokenCookieName string
	CSRFTokenHeaderName string
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
	if h.CSRFTokenHeaderName == "" {
		h.CSRFTokenHeaderName = DefaultCSRFTokenHeaderName
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

func (h *CSRFHelper) validateCSRFTokenAge(tokenBytes []byte) (sessionIdent []byte, shouldRenew bool, err error) {
	t, sessionIdent := timestampFromPrependBytes(tokenBytes)
	curentTime := time.Now()
	delta := curentTime.Sub(t)
	if delta > h.MaxCSRFTokenAge {
		return nil, false, ErrTokenExpired
	}
	if delta > h.RenewCSRFTokenAge {
		shouldRenew = true
	}
	return
}

func (h *CSRFHelper) decryptToken(tokenString string) (sessionIdent []byte, shouldRenew bool, err error) {
	tokenBytes, err := h.DecryptString(tokenString)
	if nil != err {
		return
	}
	return h.validateCSRFTokenAge(tokenBytes)
}

func (h *CSRFHelper) makeEncryptedCookie(cookieName string, data []byte, maxAgeSeconds int) (c *http.Cookie, err error) {
	cookieValue, err := h.EncryptBytes(data)
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

// ClearCSRFTokenCookie set the CSRF token to empty value.
func (h *CSRFHelper) ClearCSRFTokenCookie(w http.ResponseWriter) (err error) {
	cookie, err := h.makeEncryptedCookie(h.CSRFTokenCookieName, nil, 1)
	if nil != err {
		return
	}
	http.SetCookie(w, cookie)
	return
}

// SessionIdentFromCSRFTokenCookie fetch sessionIdent from CSRF token cookie.
func (h *CSRFHelper) SessionIdentFromCSRFTokenCookie(r *http.Request) (sessionIdent []byte, shouldRenew bool, err error) {
	cookie, err := r.Cookie(h.CSRFTokenCookieName)
	if nil != err {
		if err == http.ErrNoCookie {
			return nil, false, nil
		}
		return
	}
	return h.decryptToken(cookie.Value)
}

// SessionIdentFromCSRFTokenHeader fetch sessionIdent from CSRF token header.
func (h *CSRFHelper) SessionIdentFromCSRFTokenHeader(r *http.Request) (sessionIdent []byte, shouldRenew bool, err error) {
	tokenHeader := r.Header.Get(h.CSRFTokenHeaderName)
	if tokenHeader == "" {
		return nil, false, nil
	}
	return h.decryptToken(tokenHeader)
}
