package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestVerifyHostname(t *testing.T) {
	var matches bool

	pemBlock, _ := pem.Decode([]byte(rsaCertPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading cert, got: %v", err)
	}

	matches = VerifyHostname(cert, "valid.tlstest.com")

	if !matches {
		t.Errorf("Hostname didn't match, got: %v, want: %v.", matches, true)
	}

	matches = VerifyHostname(cert, "invalid.tlstest.com")
	if matches {
		t.Errorf("Hostname shouldn't match, got: %v, want: %v.", matches, false)
	}
}
