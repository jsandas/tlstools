package ssl

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnStateGood(t *testing.T) {
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

	s := strings.Replace(server.URL, "https://", "", -1)
	host, port, _ := net.SplitHostPort(s)

	cs, _ := ConnState(host, port)

	if len(cs.PeerCertificates) != 1 {
		t.Errorf("Cert count incorrect, got: %d, want: %d.", len(cs.PeerCertificates), 1)
	}
}

func TestConnStateBad(t *testing.T) {

	_, i := ConnState("test.test.test", "443")

	if i > 0 {
		t.Errorf("Cert count incorrect, got: %d, want: %d.", i, 0)
	}
}
