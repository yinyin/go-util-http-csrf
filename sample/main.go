package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	httpcsrf "github.com/yinyin/go-util-http-csrf"
)

func parseCommandParam() (httpAddr string, keyBinary []byte, hashMask uint32) {
	var keyText string
	var hashMask64 uint64
	flag.StringVar(&httpAddr, "listen", ":8080", "port and address to listen on")
	flag.StringVar(&keyText, "key", "", "encryption key for CSRF token")
	flag.Uint64Var(&hashMask64, "mask", 7, "mask value for masking hash")
	flag.Parse()
	var err error
	if keyText == "" {
		if keyBinary, err = httpcsrf.GenerateKey(); nil != err {
			log.Fatalf("ERROR: failed on generating key: %v", err)
			return
		}
		keyText = httpcsrf.PackKeyToString(keyBinary)
		log.Printf("INFO: Generated key: [%s]", keyText)
	} else {
		if keyBinary, err = httpcsrf.UnpackKeyFromString(keyText); nil != err {
			log.Fatalf("ERROR: failed on unpack key: %v", err)
			return
		}
	}
	hashMask = uint32(hashMask64 & 0xFFFFFFFF)
	return
}

func main() {
	httpAddr, keyBinary, hashMask := parseCommandParam()
	log.Printf("INFO: listen on address: [%s]", httpAddr)
	h := &sampleHandler{}
	h.csrfHelper.KeyBinary = keyBinary
	h.csrfHelper.HashMask = hashMask
	h.csrfHelper.CookiePath = "/"
	h.csrfHelper.MaxCSRFTokenAge = time.Minute * 2
	h.csrfHelper.RenewCSRFTokenAge = time.Minute
	if err := h.csrfHelper.Initialize(); nil != err {
		log.Fatalf("ERR: cannot initialize CSRF helper: %v", err)
		return
	}
	h.sessionIdent = []byte("=SessionIdent=")
	s := &http.Server{
		Addr:         httpAddr,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(s.ListenAndServe())
}
