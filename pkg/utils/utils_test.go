package utils

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanConnect(t *testing.T) {
	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/" {
			// Send response to be tested
			rw.Write([]byte("hello"))
		}
	}))
	// Close the server when test finishes
	defer server.Close()

	s := strings.Split(strings.Replace(server.URL, "http://", "", -1), ":")
	host := s[0]
	port := s[1]
	c := CanConnect(host, port)

	if !c {
		t.Errorf("CanConnect failed, got: %v, want: %v.", c, true)
	}
}

func TestCanConnectError(t *testing.T) {
	c := CanConnect("localhost", "80")

	if c {
		t.Errorf("CanConnect succeeded, got: %v, want: %v.", c, true)
	}
}

func TestDownloadBinFile(t *testing.T) {
	var b = []byte("hello")
	var l = len(b)

	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/" {
			// Send response to be tested
			rw.Write(b)
		}
	}))
	// Close the server when test finishes
	defer server.Close()

	r, _ := DownloadBINFile(server.URL + "/")

	if len(r) != l {
		t.Errorf("failed to download data, got: %d, want: %d.", len(r), l)
	}
}

func TestGenRandBytes(t *testing.T) {
	r, _ := GenRandBytes(32)

	if len(r) != 32 {
		t.Errorf("wrong random bytes length, got: %d, want: %d.", len(r), 32)
	}
}

func TestBytetoInt(t *testing.T) {
	b, _ := hex.DecodeString("8034")
	expI := 32820

	i := BytetoInt(b)

	if i != expI {
		t.Errorf("can connect failed, got: %d, want: %d.", i, expI)
	}
}

func TestGetHTTPHeader(t *testing.T) {
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
	h, _ := GetHTTPHeader(host, port, "Server")

	if h != "Apache" {
		t.Errorf("failed to get server header, got: %s, want: %s.", h, "Apache")
	}
}

func TestGetService(t *testing.T) {
	var l = map[string]string{
		"21":   "ftp",
		"25":   "smtp",
		"465":  "smtpSSL",
		"587":  "smtp",
		"110":  "pop3",
		"995":  "pop3SSL",
		"143":  "imap",
		"993":  "imapSSL",
		"443":  "https",
		"3389": "rdp",
	}

	for k, v := range l {
		p := GetService(k)
		if p != v {
			t.Errorf("failed to correct service, got: %s, want: %s.", p, v)
		}
	}

}

func TestLtos(t *testing.T) {
	var str string = "testing"
	var l = []string{str}

	r := Ltos(l)
	if r != str {
		t.Errorf("did not get string, got: %s, want: %s.", l, str)
	}
}

func TestValidHost(t *testing.T) {
	var goodHost string = "test.example.com"
	var badHost string = "test.%example.com"

	if !ValidHost(goodHost) {
		t.Errorf("host should be valid: %s, got: %v, want: %v.", goodHost, false, true)
	}

	if ValidHost(badHost) {
		t.Errorf("host should not be valid: %s, got: %v, want: %v.", badHost, true, false)
	}
}

func TestValidPort(t *testing.T) {
	var goodPort string = "443"
	var badPort string = "70000"

	if !ValidPort(goodPort) {
		t.Errorf("port should be valid: %s, got: %v, want: %v.", goodPort, false, true)
	}

	if ValidPort(badPort) {
		t.Errorf("port should not be valid: %s, got: %v, want: %v.", badPort, true, false)
	}
}
