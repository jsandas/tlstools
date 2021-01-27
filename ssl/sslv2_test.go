package ssl

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMakeClientHello(t *testing.T) {

	var pstr string = "8034010002001b00000010"
	var sstr string = "2922beb35a018b04fe5f8003a013ebc4"
	var l int = 108

	clientHello := hex.EncodeToString(makeClientHello())

	if !strings.HasPrefix(clientHello, pstr) {
		t.Errorf("ClientHello prefix incorrect, got: %s, want: %s", clientHello, pstr)
	}
	if !strings.HasSuffix(clientHello, sstr) {
		t.Errorf("ClientHello suffix incorrect, got: %s, want: %s", clientHello, sstr)
	}
	if len(clientHello) != l {
		t.Errorf("ClientHello length incorrect, got: %d, want: %d", len(clientHello), l)
	}
}

// This check will break if the admin of
// mlreport.infraware.co.kr disables sslv2 support
func TestSSLv2Check(t *testing.T) {
	var host string = "mlreport.infraware.co.kr"
	var port string = "443"
	r := sslv2Check(host, port)
	if _, ok := r["SSLv2"]; !ok {
		t.Errorf("sslv2 check failed, host: %s:%s", host, port)
	}
}

// server does not support sslv2
func TestCheckNoSSLv2(t *testing.T) {
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
	r := sslv2Check(host, port)
	if _, ok := r["SSLv2"]; ok {
		t.Errorf("sslv2 check should have failed, host: %s:%s", host, port)
	}
}

// tcp dial error
func TestCheckError(t *testing.T) {
	var host string = "test.local"
	var port string = "443"
	r := sslv2Check(host, port)
	if _, ok := r["SSLv2"]; ok {
		t.Errorf("sslv2 check should have failed, host: %s:%s", host, port)
	}
}

func TestSSLv2GetCiphers(t *testing.T) {
	// 030080 080080 020080
	var cstr = []string{"SSL2_RC2_128_CBC_WITH_MD5", "SSL2_RC4_64_WITH_MD5", "SSL2_RC4_128_EXPORT40_WITH_MD5"}

	bytes, _ := hex.DecodeString("83bf0400010002038f00090300800800800200807f593d3b350aa013a97e648f591a8c98")

	c := sslv2GetCiphers(bytes)

	for i := range c {
		if c[i] != cstr[i] {
			t.Errorf("wrong ciphers, got: %s, want: %s", c, cstr)
		}
	}
}
