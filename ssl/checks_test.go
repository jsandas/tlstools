package ssl

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnect(t *testing.T) {
	// Start a local HTTPS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/" {
			// Send response to be tested
			rw.Header().Set("Server", "Apache")
			rw.Write([]byte("Hello"))
		}
	}))
	// Close the server when test finishes
	defer server.Close()

	s := strings.Split(strings.Replace(server.URL, "https://", "", -1), ":")
	host := s[0]
	port := s[1]

	// SSLv3/TLS_RSA_WITH_AES_128_CBC_SHA no go
	b1 := connect(host, port, VersionSSL30, TLS_RSA_WITH_AES_128_CBC_SHA)
	if b1 {
		t.Errorf("should not have connected, got: %v, want: %v.", b1, false)
	}

	// TLSv1.2/TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 go
	b2 := connect(host, port, tls.VersionTLS12, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
	if !b2 {
		t.Errorf("should have connected, got: %v, want: %v.", b2, true)
	}
}

func TestCheck(t *testing.T) {
	// create local https server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/" {
			// Send response to be tested
			rw.Header().Set("Server", "Apache")
			rw.Write([]byte("Hello"))
		}
	}))
	server.TLS = &tls.Config{
		// CipherSuites: uint16[],
		MinVersion: uint16(VersionTLS12),
		MaxVersion: uint16(VersionTLS13),
	}
	// Start a local HTTPS server
	server.StartTLS()

	// Close the server when test finishes
	defer server.Close()

	s := strings.Split(strings.Replace(server.URL, "https://", "", -1), ":")
	host := s[0]
	port := s[1]
	l := Check(host, port, "RSA")

	// if less than 4 protocols supported
	if len(l) != 2 {
		t.Errorf("protocol count incorrect, got: %d, want: %d.", len(l), 2)
	}
}
