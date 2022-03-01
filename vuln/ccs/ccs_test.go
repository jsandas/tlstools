package ccs

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
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

	status := Check(host, port)

	if status != "no" {
		t.Errorf("Wrong return, got: %s, want: %s.", status, "no")
	}
}

// disabled check because I cannot find a server with the heartbeat
// extension enabled
// func TestBleedSafe(t *testing.T) {
// 	status := Heartbleed("seal.digicert.com", "443", 771)

// 	if status != "no" {
// 		t.Errorf("Wrong return, got: %s, want: %s.", status, "no")
// 	}
// }
