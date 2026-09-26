package enforcement

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Errors returned by Enforce.
var (
	ErrDeniedByPolicy     = errors.New("enforcement: denied by policy")
	ErrNilTarget          = errors.New("enforcement: target url is nil")
	ErrInvalidTarget      = errors.New("enforcement: target url is invalid")
	ErrTargetNotPermitted = errors.New("enforcement: target is not the configured upstream")
)

type EnforcementPoint interface {
	Enforce(w http.ResponseWriter, r *http.Request, allowed bool, target *url.URL) error
}

type ReverseProxyEnforcer struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func NewReverseProxyEnforcer(target *url.URL) (*ReverseProxyEnforcer, error) {
	if target == nil {
		return nil, ErrNilTarget
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, ErrInvalidTarget
	}
	if target.Host == "" {
		return nil, ErrInvalidTarget
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	baseDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		baseDirector(req)
		req.Host = target.Host
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Host")
		req.Header.Del("X-Forwarded-Proto")

		for name := range req.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-aether-") {
				req.Header.Del(name)
			}
		}
		req.Header.Set("X-Aether-Decision", "allow")
	}

	proxy.Transport = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[ENFORCEMENT] upstream error: %v", err)
		writeJSONStatus(w, http.StatusBadGateway, `{"error":"upstream unavailable"}`)
	}

	return &ReverseProxyEnforcer{target: target, proxy: proxy}, nil
}

func (e *ReverseProxyEnforcer) Target() *url.URL {
	return e.target
}

func (e *ReverseProxyEnforcer) Enforce(w http.ResponseWriter, r *http.Request, allowed bool, target *url.URL) error {
	if !allowed {
		writeForbidden(w)
		return ErrDeniedByPolicy
	}
	if target == nil {
		writeForbidden(w)
		return ErrNilTarget
	}
	if target.Scheme != e.target.Scheme || target.Host != e.target.Host {
		writeForbidden(w)
		return ErrTargetNotPermitted
	}

	e.proxy.ServeHTTP(w, r)
	return nil
}

func writeForbidden(w http.ResponseWriter) {
	writeJSONStatus(w, http.StatusForbidden, `{"error":"forbidden"}`)
}

func writeJSONStatus(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(body))
}
