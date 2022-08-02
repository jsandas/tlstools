package ssl

import (
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestCheckSSLv2(t *testing.T) {
	// Start the new server.
	srv, _ := net.Listen("tcp", ":443")
	defer srv.Close()

	var srvConn net.Conn

	go func() {
		srvConn, _ = srv.Accept()

		// sslv2 serverHello message
		sh, _ := hex.DecodeString("83bf0400010002038f001500103082038b30820273a003020102020900f6c1e643a8fbe5e6300d06092a864886f70d0101050500305c310b3009060355040613025553310f300d06035504080c0644656e69616c3114301206035504070c0b537072696e676669656c64310c300a060355040a0c034469733118301606035504030c0f7777772e6578616d706c652e636f6d301e170d3232303733313230333031345a170d3233303733313230333031345a305c310b3009060355040613025553310f300d06035504080c0644656e69616c3114301206035504070c0b537072696e676669656c64310c300a060355040a0c034469733118301606035504030c0f7777772e6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100dce452e012a918968234868f778290ef6b53f45cc00ec743b69c2a850a59e9615b60185d414a4dab8aa30a30dc5d65c56e15e1851e8b3693b0824fc217fb0ac8fe6d515d0c65677a93728dcb9ad5e476e5b960f7c0810c745d56dbde9364b1089547070a7563c6bdd57ae9bb04757e63e301b318244745fdf4618186e5b83bdd2acfa0a0df851e260d3b44d4df41bdeff0a659764702f72b674ad9b6dd884074e2d4334ad845f48b632706a51968a65bcf400b144b6a85c5c5e6bec5ae15afc03538bade516fab1238ca4cf734bfc70300a6065a251507e2c83d899ebaab8fe085cfc5671b961d46b76e7e5e667048454e560e43c2dabac5940f655058d51ab10203010001a350304e301d0603551d0e04160414547fc8a25cf8e6cf3df5de0716d7efb88645c2e3301f0603551d23041830168014547fc8a25cf8e6cf3df5de0716d7efb88645c2e3300c0603551d13040530030101ff300d06092a864886f70d01010505000382010100a516dd9ccf868b11ec8b3a528f8c04796e1a299a1cf95a4770d98598029328c40dddfefcb081311ea66617338abc7b9e3251bef225d8c8421586696d69077d6e0bc8228e60725cfdcf68f412efa630f61240d3aeae4ab9d54af0535aed80446058219a7459dc33a0cb04f0b0041894e8f14d800bbc407d11be243f937ba6c58ec1aa722de42a90e1b37956dfb3a040db14385df5d7da285bb1787bacac1c55021c6e50ff4d34777ad6addf26a94ed9c20fa2d07d1780f61115a5b43db64a8ee92d0f818cd25a7bb837b66477d49cf27dbfc7fc8175177852aba2d496b65e2bab3b91a488950c7ac4669ccd1a2098f10e212b8aba322a72b2eb765e06fd641aa30700c00500800300800100800600400400800200801ba6246f75157f2265e86f23f73774f0")

		srvConn.Write(sh)
		time.Sleep(1 * time.Second)
	}()

	host := "localhost"
	port := "443"
	r := sslv2Check(host, port)
	if _, ok := r["SSLv2"]; !ok {
		t.Errorf("sslv2 check should have succeeded, host: %s:%s", host, port)
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
