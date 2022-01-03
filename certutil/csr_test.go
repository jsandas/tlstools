package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParseRSACSR(t *testing.T) {
	var c CSRData

	pemBlock, _ := pem.Decode([]byte(rsaCSRPEM))
	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading csr, got: %v", err)
	}

	c.Process(*csr)

	if c.Subject.CountryName != "US" {
		t.Errorf("Certificate incorrect common name, got: %s, want: %s.", c.Subject.CountryName, "AU")
	}

	if c.KeyType != "RSA-2048" {
		t.Errorf("Certificate incorrect key size, got: %s, want: %s.", c.KeyType, "ECDSA-521")
	}

	if c.Version != 0 {
		t.Errorf("Certificate incorrect serial number, got: %d, want: %d.", c.Version, 0)
	}
}

func TestParseECDSACSR(t *testing.T) {
	var c CSRData

	pemBlock, _ := pem.Decode([]byte(ecdsaCSRPEM))
	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading csr, got: %v", err)
	}

	c.Process(*csr)

	if c.Subject.CountryName != "US" {
		t.Errorf("Certificate incorrect common name, got: %s, want: %s.", c.Subject.CountryName, "AU")
	}

	if c.KeyType != "ECDSA-253" {
		t.Errorf("Certificate incorrect key size, got: %s, want: %s.", c.KeyType, "RSA-2048")
	}

	if c.Version != 0 {
		t.Errorf("Certificate incorrect serial number, got: %d, want: %d.", c.Version, 0)
	}
}
