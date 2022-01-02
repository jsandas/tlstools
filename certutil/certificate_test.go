package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const (
	rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDbjCCAlagAwIBAgIBATANBgkqhkiG9w0BAQsFADBpMRkwFwYDVQQDDBBTZWxm
LVNpZ25lZCBSb290MQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExFzAVBgNVBAcM
DlNvbWV3aGVyZSBDaXR5MRkwFwYDVQQKDBBTZWxmLVNpZ25lZCBJbmMuMB4XDTIx
MTEwOTAzMjIyNloXDTMxMTEwNzAzMjIyNlowajELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAldBMRcwFQYDVQQHDA5Tb21ld2hlcmUgQ2l0eTEZMBcGA1UECgwQU2VsZi1T
aWduZWQgSW5jLjEaMBgGA1UEAwwRdmFsaWQudGxzdGVzdC5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnSNfZUbiKQVt+pTHEhFiEFejOgMRJq0+U
z76Ja2F78ksYHK5kUgJVUb4ZOpHz0uENNBeCeRBQuFOGsKBmMZgIie5ZRXX7/UsM
EULAvrdcxr23/TND65iEEKt1Az66GBHdejnbYDLdgzTrH7cbFW3G3Xvsq5RNw4Yj
MNXziMj84msCx/QmNjJJZQ8UCU6wkgZ2ZTbFmfjm+k/LbDT4G52/LUC3Vb97bcKv
UQ1RwNwXpRrxtUcsBgAc6u+0StlAdYLgkVryEIX1yBrT4gvCxikwJb6q8B9IQEwP
n7Hw/zWsl2344wyXz6Pyv4yTmb6GHZauj0s5eo84hpk3R+I1NeuzAgMBAAGjIDAe
MBwGA1UdEQQVMBOCEXZhbGlkLnRsc3Rlc3QuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQBG2oIst35Wj9lk4LgYH3PIa4U33Yd1pue6QneHu+7Auobka181WJIMSHzIR1/B
60vUj7grLRUCGjbq6/jayTLTA229rifv2g9g3Vz+GP2bCyZfgWiIOYSWxUtCxBFT
GGwnjv0u1M9awG1YjzElVoZBqKAQdfx0J6NRBNgnJvQ6TzREMhA5V2sdoynOmyu5
90vKd7DlLVGg1cZx7WmGSI6ymVHYahOVz7dxH2FpxVQ3j5L7FFcxiOaffI58ccza
zfCNBbx/lvknjXwMf0wDLJQwMvqBkZ3qdDdooukicF5yIXjNFVBqJNJOvDOdo10U
VqXWhGr3Fdkg4Bm8H6ZRkvD1
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

	// 	nonsensePEM = `
	// -----BEGIN NONSENSE-----
	// Zm9vZm9vZm9v
	// -----END NONSENSE-----`

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
	var c CertData

	pemBlock, _ := pem.Decode([]byte(rsaCertPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading cert, got: %v", err)
	}

	c.Process(cert)

	if c.Subject.CommonName != "valid.tlstest.com" {
		t.Errorf("Certificate incorrect common name, got: %s, want: %s.", c.Subject.CommonName, "valid.tlstest.com")
	}

	if c.KeyType != "RSA-2048" {
		t.Errorf("Certificate incorrect key size, got: %s, want: %s.", c.KeyType, "RSA-2048")
	}

	if c.SerialNumber != "01" {
		t.Errorf("Certificate incorrect serial number, got: %s, want: %s.", c.SerialNumber, "01")
	}
}

func TestParseECDSACert(t *testing.T) {
	var c CertData

	pemBlock, _ := pem.Decode([]byte(ecdsaCertPEM))
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Errorf("Error reading cert, got: %v", err)
	}

	c.Process(cert)

	if c.Subject.CountryName != "AU" {
		t.Errorf("Certificate incorrect common name, got: %s, want: %s.", c.Subject.CountryName, "AU")
	}

	if c.KeyType != "ECDSA-521" {
		t.Errorf("Certificate incorrect key size, got: %s, want: %s.", c.KeyType, "ECDSA-521")
	}

	if c.SerialNumber != "EC71D531C35E9714" {
		t.Errorf("Certificate incorrect serial number, got: %s, want: %s.", c.SerialNumber, "EC71D531C35E9714")
	}
}
