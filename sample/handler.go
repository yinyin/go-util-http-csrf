package main

import (
	"log"
	"net/http"

	httphandlers "github.com/yinyin/go-util-http-handlers"

	httpcsrf "github.com/yinyin/go-util-http-csrf"
)

type sampleHandler struct {
	csrfHelper   httpcsrf.CSRFHelper
	sessionIdent []byte
}

func (h *sampleHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet, http.MethodPost:
		break
	default:
		http.Error(w, "not allow: "+req.Method, http.StatusMethodNotAllowed)
		return
	}
	log.Printf("DEBUG: method=%s; path=%s", req.Method, req.URL.Path)
	switch req.URL.Path {
	case "/endpoint/gen-token":
		if err := h.csrfHelper.SetCSRFTokenCookie(w, h.sessionIdent); nil != err {
			http.Error(w, "SetCSRFTokenCookie: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var result struct {
			Success bool `json:"success"`
		}
		result.Success = true
		if err := httphandlers.JSONResponse(w, &result); nil != err {
			log.Printf("ERROR: JSONResponse (gen-token): %v", err)
		}
		return
	case "/endpoint/validate-token":
		sessionIdent, shouldRenew, err := h.csrfHelper.SessionIdentFromCSRFTokenHeader(req)
		if nil != err {
			if err == httpcsrf.ErrTokenExpired {
				http.Error(w, "ErrTokenExpired", http.StatusForbidden)
			} else {
				http.Error(w, "SessionIdentFromCSRFTokenHeader: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if shouldRenew {
			if err := h.csrfHelper.SetCSRFTokenCookie(w, h.sessionIdent); nil != err {
				http.Error(w, "SetCSRFTokenCookie: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		log.Printf("DEBUG: (validate-token) sessionIdent: %v; shouldRenew: %v", sessionIdent, shouldRenew)
		var result struct {
			SessionIdent string `json:"session"`
			HadRenew     bool   `json:"renew"`
		}
		result.SessionIdent = string(sessionIdent)
		result.HadRenew = shouldRenew
		if err = httphandlers.JSONResponse(w, &result); nil != err {
			log.Printf("ERROR: JSONResponse (validate-token): %v", err)
		}
		return
	case "/endpoint/session-ident":
		sessionIdent, shouldRenew, err := h.csrfHelper.SessionIdentFromCSRFTokenCookie(req)
		if nil != err {
			if err == httpcsrf.ErrTokenExpired {
				http.Error(w, "ErrTokenExpired", http.StatusForbidden)
			} else {
				http.Error(w, "SessionIdentFromCSRFTokenCookie: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		log.Printf("DEBUG: (session-ident) sessionIdent: %v; shouldRenew: %v", sessionIdent, shouldRenew)
		var result struct {
			SessionIdent string `json:"session"`
			ShouldRenew  bool   `json:"should_renew"`
		}
		result.SessionIdent = string(sessionIdent)
		result.ShouldRenew = shouldRenew
		if err = httphandlers.JSONResponse(w, &result); nil != err {
			log.Printf("ERROR: JSONResponse (session-ident): %v", err)
		}
		return
	case "/debug/cookies":
		var result struct {
			Cookies []*http.Cookie `json:"cookies"`
		}
		result.Cookies = req.Cookies()
		if err := httphandlers.JSONResponse(w, &result); nil != err {
			log.Printf("ERROR: JSONResponse (debug/cookies): %v", err)
		}
		return
	case "/debug/headers":
		var result struct {
			Headers http.Header `json:"headers"`
		}
		result.Headers = req.Header
		if err := httphandlers.JSONResponse(w, &result); nil != err {
			log.Printf("ERROR: JSONResponse (debug/headers): %v", err)
		}
		return
	}
	http.NotFound(w, req)
}
