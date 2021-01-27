package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const (
	rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDRzCCAi8CAQEwDQYJKoZIhvcNAQELBQAwaTEZMBcGA1UEAwwQU2VsZi1TaWdu
ZWQgUm9vdDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRcwFQYDVQQHDA5Tb21l
d2hlcmUgQ2l0eTEZMBcGA1UECgwQU2VsZi1TaWduZWQgSW5jLjAeFw0yMDA0Mjcx
NTE3MjBaFw0yMDA1MDQxNTE3MjBaMGoxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJX
QTEXMBUGA1UEBwwOU29tZXdoZXJlIENpdHkxGTAXBgNVBAoMEFNlbGYtU2lnbmVk
IEluYy4xGjAYBgNVBAMMEXZhbGlkLnRsc3Rlc3QuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA9AJd4A4ikltaWOI7newVDbJVsA5ZL3zlri9y7mMD
rrPMZJURoopOx50gmfcllfrY5TfzCDw+Xnu/jqhZ7UoPRay64ZJTaYhajdtTPj7N
V4wIF5SpZNgQSMbZ2OLEQwanrrOfbzEmh4PqUUKQBYgqQ3f2B3Y341NZo36VDPj2
Gph+uYeZ1/0HKPAxPeOmFDEHcX5cgV2RqzSFkfMrqlwX9MFG4te2fXarf8h4bR2q
mVzT+A0m+q42fbSHPZr5hD6T2CoONW2i2021ztFAD84cee673Yc0us84UCaoslUu
X9ri8Mkya9lCjZyqOLdBfbahPZR98YvDX88AI2/7IkFThwIDAQABMA0GCSqGSIb3
DQEBCwUAA4IBAQCKQo7ZpCwJZXwhd9veyrM7UQbAhHjeQNv9qdsQUNsBIFB1mPlt
U4R/ipyamBjHtAxLBEPJ5zrkCm7W2V02H1BNgsj0p3KFRoRfZgtI3czIdjfvSpWD
u2XXUF2vyX4NtAOCDMAcRabLcTYfoLxnBBpf8zc3+WVycN/IPSSEgkSbLSdieQ11
OOBubdLmcOGwEXiUAY1uFwwZv1IZadQTNRlpkP2R1Xv6SzqMf/l0Gb/s+hXZaYGI
9SaBnmt9TwD/PHo2hB2NH/YosoLNDR/i5cB8YMAalCS4Alt1pGty33EUuCjiw33E
qEBqXT81L/84EE0R0Io2Em08GkGNn950AR2O
-----END CERTIFICATE-----`

	ecdsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB/jCCAWICCQDscdUxw16XFDAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTI0MDQ4WhcNMTUxMTE0MTI0MDQ4WjBFMQswCQYDVQQG
EwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lk
Z2l0cyBQdHkgTHRkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBY9+my9OoeSUR
lDQdV/x8LsOuLilthhiS1Tz4aGDHIPwC1mlvnf7fg5lecYpMCrLLhauAc1UJXcgl
01xoLuzgtAEAgv2P/jgytzRSpUYvgLBt1UA0leLYBy6mQQbrNEuqT3INapKIcUv8
XxYP0xMEUksLPq6Ca+CRSqTtrd/23uTnapkwCQYHKoZIzj0EAQOBigAwgYYCQXJo
A7Sl2nLVf+4Iu/tAX/IF4MavARKC4PPHK3zfuGfPR3oCCcsAoz3kAzOeijvd0iXb
H5jBImIxPL4WxQNiBTexAkF8D1EtpYuWdlVQ80/h/f4pBcGiXPqX5h2PQSQY7hP1
+jwM1FGS4fREIOvlBYr/SzzQRtwrvrzGYxDEDbsC0ZGRnA==
-----END CERTIFICATE-----`

	nonsensePEM = `
-----BEGIN NONSENSE-----
Zm9vZm9vZm9v
-----END NONSENSE-----`

	rsaCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIDJjCCAg4CAQAwajEaMBgGA1UEAwwRdmFsaWQudGxzdGVzdC5jb20xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJXQTEXMBUGA1UEBwwOU29tZXdoZXJlIENpdHkxGTAX
BgNVBAoMEFNlbGYtU2lnbmVkIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQD0Al3gDiKSW1pY4jud7BUNslWwDlkvfOWuL3LuYwOus8xklRGiik7H
nSCZ9yWV+tjlN/MIPD5ee7+OqFntSg9FrLrhklNpiFqN21M+Ps1XjAgXlKlk2BBI
xtnY4sRDBqeus59vMSaHg+pRQpAFiCpDd/YHdjfjU1mjfpUM+PYamH65h5nX/Qco
8DE946YUMQdxflyBXZGrNIWR8yuqXBf0wUbi17Z9dqt/yHhtHaqZXNP4DSb6rjZ9
tIc9mvmEPpPYKg41baLbTbXO0UAPzhx57rvdhzS6zzhQJqiyVS5f2uLwyTJr2UKN
nKo4t0F9tqE9lH3xi8NfzwAjb/siQVOHAgMBAAGgdzB1BgkqhkiG9w0BCQ4xaDBm
MBoGA1UdEQQTMBGCD3Nhbi50bHN0ZXN0LmNvbTAJBgNVHRMEAjAAMB0GA1UdDgQW
BBRUBcM9J8Xa/PuHOZj+iXetjhzzMjALBgNVHQ8EBAMCA/gwEQYJYIZIAYb4QgEB
BAQDAgTwMA0GCSqGSIb3DQEBCwUAA4IBAQBHWZzBPH9POzoPEjyHMg6066/cgqR1
KkaTGu2vJyN5RVwVBN5bNVrpc49vJBfzHcwKIyPB0zrqK/C1HSl/fqTNPn7VMif+
In3tFlYaGApN/P4/Ya45d4Ji7unSk+CyAo7c/yW+/5MHW6HB7Gy/W+pE7AB7KFj+
nHoD053h64Fh5ko+B7ELzUGqzfwkkN4Ej9UCDWF9e87HujeJzIx1AFPbkBshOyhG
/8g4WCVuTrXyKrKdYVJRGiM0Mijroi1R64bqckhUKvytwEG09Wkh0wpSGm91U0Dz
5nCQlQY+7bZLwNpRFvAV2WKPjsULHgXjCdsNr77swuiuF1SANSm0mlre
-----END CERTIFICATE REQUEST-----`

	ecdsaCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIIBGzCBwgIBADBgMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTUQxETAPBgNVBAcM
CFRlc3RDaXR5MRUwEwYDVQQKDAxFeGFtcGxlIEluYy4xGjAYBgNVBAMMEWVjZHNh
LmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHLyc5o1XhH6+
Xt2DHBjXDubUxuxXwVzPIT5cHjZzaisl0LtX+ZaK/biA+mEMtFvYAErky2YDdV8x
wCH8ZY/y3aAAMAoGCCqGSM49BAMCA0gAMEUCICOQqKu2s9yq9yibqxvU69C0z8Q4
J8dspgDPuJbcpsTjAiEA4nhWH5rVKB3kN0h055d6ga4Dw66XlU/tgOu6Ek8GliY=
-----END CERTIFICATE REQUEST-----`
)

func TestIsTrusted(t *testing.T) {
	var certList []*x509.Certificate

	pemBlock, _ := pem.Decode([]byte(rsaCertPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading cert, got: %v", err)
	}
	certList = append(certList, cert)

	trusted := IsTrusted(certList, "valid.tlstest.com")

	if trusted {
		t.Errorf("Certificate shouldn't be trusted, got: %v, want: %v.", trusted, false)
	}
}

func TestParseRSACert(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(rsaCertPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading cert, got: %v", err)
	}

	parsedCert := ParseCert(cert)

	if parsedCert.Subject.CommonName != "valid.tlstest.com" {
		t.Errorf("Certificate incorrect common name, got: %s, want: %s.", parsedCert.Subject.CommonName, "valid.tlstest.com")
	}

	if parsedCert.KeyType != "RSA-2048" {
		t.Errorf("Certificate incorrect key size, got: %s, want: %s.", parsedCert.KeyType, "RSA-2048")
	}

	if parsedCert.SerialNumber != "01" {
		t.Errorf("Certificate incorrect serial number, got: %s, want: %s.", parsedCert.SerialNumber, "01")
	}
}

func TestParseECDSACert(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(ecdsaCertPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading cert, got: %v", err)
	}

	parsedCert := ParseCert(cert)

	if parsedCert.Subject.CountryName != "AU" {
		t.Errorf("Certificate incorrect common name, got: %s, want: %s.", parsedCert.Subject.CountryName, "AU")
	}

	if parsedCert.KeyType != "ECDSA-521" {
		t.Errorf("Certificate incorrect key size, got: %s, want: %s.", parsedCert.KeyType, "ECDSA-521")
	}

	if parsedCert.SerialNumber != "EC71D531C35E9714" {
		t.Errorf("Certificate incorrect serial number, got: %s, want: %s.", parsedCert.SerialNumber, "EC71D531C35E9714")
	}
}

func TestParseRSACSR(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(rsaCSRPEM))
	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading csr, got: %v", err)
	}

	parsedCSR := ParseCSR(*csr)

	if parsedCSR.Subject.CountryName != "US" {
		t.Errorf("Certificate incorrect common name, got: %s, want: %s.", parsedCSR.Subject.CountryName, "AU")
	}

	if parsedCSR.KeyType != "RSA-2048" {
		t.Errorf("Certificate incorrect key size, got: %s, want: %s.", parsedCSR.KeyType, "ECDSA-521")
	}

	if parsedCSR.Version != 0 {
		t.Errorf("Certificate incorrect serial number, got: %d, want: %d.", parsedCSR.Version, 0)
	}
}

func TestParseECDSACSR(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(ecdsaCSRPEM))
	csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading csr, got: %v", err)
	}

	parsedCSR := ParseCSR(*csr)

	if parsedCSR.Subject.CountryName != "US" {
		t.Errorf("Certificate incorrect common name, got: %s, want: %s.", parsedCSR.Subject.CountryName, "AU")
	}

	if parsedCSR.KeyType != "ECDSA-253" {
		t.Errorf("Certificate incorrect key size, got: %s, want: %s.", parsedCSR.KeyType, "RSA-2048")
	}

	if parsedCSR.Version != 0 {
		t.Errorf("Certificate incorrect serial number, got: %d, want: %d.", parsedCSR.Version, 0)
	}
}

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
