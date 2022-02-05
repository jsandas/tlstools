package ccs

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBleedNotEnabled(t *testing.T) {
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

	status := Heartbleed(host, port, 771)

	if status != "n/a" {
		t.Errorf("Wrong return, got: %s, want: %s.", status, "n/a")
	}

	statusTLS13 := Heartbleed(host, port, 772)

	if statusTLS13 != "n/a" {
		t.Errorf("Wrong return, got: %s, want: %s.", status, "n/a")
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

func TestBleedTimeout(t *testing.T) {
	status := Heartbleed("127.0.0.1", "4242", 771)

	if status != "error" {
		t.Errorf("Wrong return, got: %s, want: %s.", status, "error")
	}
}
