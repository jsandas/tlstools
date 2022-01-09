package status

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jsandas/tlstools/ssl"
)

var expiredOCSPReponse = []byte{48, 130, 1, 211, 10, 1, 0, 160, 130, 1, 204, 48, 130, 1, 200, 6, 9, 43, 6, 1, 5, 5, 7, 48, 1, 1, 4, 130, 1, 185, 48, 130, 1, 181, 48, 129, 158, 162, 22, 4, 20, 61, 211, 80, 165, 214, 160, 173, 238, 243, 74, 96, 10, 101, 211, 33, 212, 248, 248, 214, 15, 24, 15, 50, 48, 49, 57, 48, 54, 51, 48, 48, 51, 51, 56, 53, 57, 90, 48, 115, 48, 113, 48, 73, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, 73, 244, 189, 138, 24, 191, 118, 6, 152, 197, 222, 64, 45, 104, 59, 113, 106, 228, 230, 134, 4, 20, 61, 211, 80, 165, 214, 160, 173, 238, 243, 74, 96, 10, 101, 211, 33, 212, 248, 248, 214, 15, 2, 16, 14, 189, 159, 131, 207, 164, 231, 214, 48, 71, 4, 120, 191, 234, 111, 219, 128, 0, 24, 15, 50, 48, 49, 57, 48, 54, 51, 48, 48, 51, 51, 56, 53, 57, 90, 160, 17, 24, 15, 50, 48, 49, 57, 48, 55, 48, 55, 48, 50, 53, 51, 53, 57, 90, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 72, 196, 141, 232, 176, 162, 200, 175, 49, 250, 230, 62, 58, 103, 234, 18, 119, 163, 93, 166, 156, 144, 36, 112, 106, 88, 17, 64, 122, 252, 138, 157, 42, 176, 49, 9, 239, 168, 130, 79, 122, 229, 219, 209, 70, 206, 173, 123, 245, 8, 252, 6, 32, 135, 56, 70, 36, 132, 122, 33, 204, 113, 113, 2, 75, 21, 233, 179, 87, 8, 6, 114, 38, 132, 209, 66, 104, 80, 216, 10, 7, 219, 140, 218, 109, 246, 228, 11, 44, 149, 23, 27, 98, 241, 103, 78, 152, 203, 210, 154, 33, 243, 227, 179, 163, 4, 185, 118, 44, 27, 179, 235, 247, 238, 111, 118, 62, 43, 255, 245, 235, 86, 204, 161, 26, 130, 68, 114, 75, 119, 90, 13, 32, 97, 94, 32, 89, 154, 155, 192, 247, 188, 168, 162, 13, 75, 73, 4, 101, 250, 21, 99, 137, 164, 231, 191, 203, 160, 195, 14, 32, 166, 251, 167, 137, 254, 185, 59, 86, 143, 50, 93, 117, 224, 90, 140, 131, 77, 111, 152, 253, 207, 214, 175, 235, 195, 9, 243, 38, 194, 42, 48, 44, 191, 206, 215, 80, 103, 70, 200, 115, 110, 65, 69, 101, 44, 208, 38, 90, 97, 189, 8, 56, 6, 219, 203, 166, 177, 6, 208, 244, 199, 47, 95, 104, 99, 68, 200, 141, 148, 187, 217, 165, 68, 18, 106, 221, 251, 99, 29, 247, 122, 91, 51, 198, 75, 35, 187, 242, 228, 107, 84, 2, 128, 65, 211}

func TestOCSPWithExpiredResponse(t *testing.T) {

	testResponse := OCSP(expiredOCSPReponse, nil)

	if testResponse != "ocsp_expired" {
		t.Errorf("OCSP staple response incorrect, got: %s, want: %s.", testResponse, "ocsp_expired")
	}
}

func TestOCSPWithValidCertificate(t *testing.T) {
	tlsConnState, _ := ssl.ConnState("www.digicert.com", "443")
	cert := tlsConnState.PeerCertificates[0]

	testResponse := OCSP(nil, cert)

	if testResponse != "successful" {
		t.Errorf("OCSP staple response incorrect, got: %s, want: %s.", testResponse, "ocsp_expired")
	}
}

func TestCheckCRLExpired(t *testing.T) {
	certSerial := "01EF67"
	crlBytes, err := ioutil.ReadFile("testrevocationfiles/test.crl.expired")
	if err != nil {
		t.Errorf("Error reading crl file, got: %v", err)
	}
	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/" {
			// Send response to be tested
			rw.Write(crlBytes)
		}
	}))
	// Close the server when test finishes
	defer server.Close()

	// Use Client & URL from our local test server
	crlData, _ := checkCRL(certSerial, server.URL)

	if crlData != "crl_expired" {
		t.Errorf("CRL response incorrect, got: %s, want: %s.", crlData, "crl_expired")
	}
}

func TestCheckCRLRevoked(t *testing.T) {
	certSerial := "01"
	crlBytes, err := ioutil.ReadFile("testrevocationfiles/test.crl")
	if err != nil {
		t.Errorf("Error reading crl file, got: %v", err)
	}
	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/" {
			// Send response to be tested
			rw.Write(crlBytes)
		}
	}))
	// Close the server when test finishes
	defer server.Close()

	// Use Client & URL from our local test server
	crlData, _ := checkCRL(certSerial, server.URL)

	if crlData != "revoked" {
		t.Errorf("CRL response incorrect, got: %s, want: %s.", crlData, "revoked")
	}
}

func TestCRL(t *testing.T) {
	certSerial := "00"
	crlBytes, err := ioutil.ReadFile("testrevocationfiles/test.crl")
	if err != nil {
		t.Errorf("Error reading crl file, got: %v", err)
	}
	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/" {
			// Send response to be tested
			rw.Write(crlBytes)
		}
	}))
	// Close the server when test finishes
	defer server.Close()

	// Use Client & URL from our local test server
	r := CRL(certSerial, []string{server.URL, server.URL})

	if r != "good" {
		t.Errorf("CRL response incorrect, got: %s, want: %s.", r, "good")
	}
}
