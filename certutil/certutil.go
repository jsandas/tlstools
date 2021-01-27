package certutil

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/jsandas/tlstools/logger"
	"github.com/jsandas/tlstools/utils"
)

// CertData certificate data fields
type CertData struct {
	// CertRaw            string            `json:"certRaw"`
	Extensions         CertExtensions    `json:"extensions"`
	Fingerprints       map[string]string `json:"fingerprints"`
	Issuer             Issuer            `json:"issuer"`
	KeyType            string            `json:"keyType"`
	SerialNumber       string            `json:"serialNumber"`
	SignatureAlgorithm string            `json:"signatureAlgorithm"`
	Status             Status            `json:"status"`
	Subject            Subject           `json:"subject"`
	ValidFrom          time.Time         `json:"validFrom"`
	ValidTo            time.Time         `json:"validTo"`
}

// CertExtensions in certificate
type CertExtensions struct {
	AuthorityInformationAccess map[string]string `json:"authorityInformationAccess"`
	CRLDistributionPoints      []string          `json:"crlDistributionPoints"`
	SubjectAlternativeNames    []string          `json:"subjectAlternativeNames"`
}

// CSRData fields
type CSRData struct {
	Extensions         CSRExtensions `json:"extensions"`
	KeyType            string        `json:"keyType"`
	SignatureAlgorithm string        `json:"signatureAlgorithm"`
	Subject            Subject       `json:"subject"`
	Version            int           `json:"version"`
}

// CSRExtensions in certificate
type CSRExtensions struct {
	SubjectAlternativeNames []string `json:"subjectAlternativeNames"`
}

// Issuer information
type Issuer struct {
	CommonName             string `json:"commonName"`
	CountryName            string `json:"countryName"`
	OrganizationalUnitName string `json:"organizationalUnitName"`
	OrganizationName       string `json:"organizationname"`
}

// Status of certificate
type Status struct {
	CRL  string
	OCSP string
}

// Subject is the fields of cert subject to keep
type Subject struct {
	CommonName             string `json:"commonName"`
	CountryName            string `json:"countryName"`
	LocalityName           string `json:"localityName"`
	OrganizationName       string `json:"organizationName"`
	OrganizationalUnitName string `json:"organizationalUnitName"`
	SerialNumber           string `json:"serialNumber"`
	StateOrProvinceName    string `json:"stateOrProvinceName"`
}

// IsTrusted checks if provided chain is trusted
func IsTrusted(certs []*x509.Certificate, host string) bool {
	cp := x509.NewCertPool()
	for _, c := range certs[1:] {
		cp.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       host,
		Intermediates: cp,
	}
	_, err := certs[0].Verify(opts)
	if err != nil {
		logger.Errorf("event_id=cert_verify_fail msg=\"%v\"", err)
		return false
	}
	return true
}

func getKeyType(pk interface{}, pka x509.PublicKeyAlgorithm) string {
	k := ""
	keySize := 0

	if pka.String() == "RSA" {
		pubKey := pk.(*rsa.PublicKey)
		keySize = pubKey.Size() * 8
	}
	if pka.String() == "ECDSA" {
		pubKey := pk.(*ecdsa.PublicKey)
		keySize = pubKey.X.BitLen()
	}

	k = fmt.Sprintf("%s-%s", pka.String(), strconv.Itoa(keySize))

	return k
}

// ParseCert used to parse/massage certain data
func ParseCert(c *x509.Certificate) CertData {
	var cert CertData
	var a = make(map[string]string)
	var e CertExtensions
	var f = make(map[string]string)
	var i Issuer
	var s Subject

	// extensions
	a["CAIssuers"] = utils.Ltos(c.IssuingCertificateURL)
	a["OCSP"] = utils.Ltos(c.OCSPServer)

	e.AuthorityInformationAccess = a
	e.CRLDistributionPoints = c.CRLDistributionPoints
	e.SubjectAlternativeNames = c.DNSNames

	//fingerprints
	h := sha1.New()
	h.Write(c.Raw)
	f["sha1"] = hex.EncodeToString(h.Sum(nil))
	h = sha256.New()
	h.Write(c.Raw)
	f["sha256"] = hex.EncodeToString(h.Sum(nil))

	// issuer data
	i.CommonName = c.Issuer.CommonName
	i.CountryName = utils.Ltos(c.Issuer.Country)
	i.OrganizationalUnitName = utils.Ltos(c.Issuer.OrganizationalUnit)
	i.OrganizationName = utils.Ltos(c.Issuer.Organization)

	// subject
	s.CommonName = c.Subject.CommonName
	s.CountryName = utils.Ltos(c.Subject.Country)
	s.LocalityName = utils.Ltos(c.Subject.Locality)
	s.OrganizationName = utils.Ltos(c.Subject.Organization)
	s.OrganizationalUnitName = utils.Ltos(c.Subject.OrganizationalUnit)
	s.SerialNumber = c.Subject.SerialNumber
	s.StateOrProvinceName = utils.Ltos(c.Subject.Province)

	// cert data
	// cert.CertRaw = base64.StdEncoding.EncodeToString(c.Raw)
	cert.Extensions = e
	cert.Fingerprints = f
	cert.Issuer = i
	cert.KeyType = getKeyType(c.PublicKey, c.PublicKeyAlgorithm)
	cert.SerialNumber = getSerialString(c.SerialNumber)
	cert.SignatureAlgorithm = c.SignatureAlgorithm.String()
	cert.Subject = s
	cert.ValidFrom = c.NotBefore
	cert.ValidTo = c.NotAfter

	return cert
}

// ParseCSR returns data from provided csr
func ParseCSR(csr x509.CertificateRequest) CSRData {
	var csrData CSRData
	var e CSRExtensions
	var s Subject

	// extensions
	e.SubjectAlternativeNames = csr.DNSNames

	// subject
	s.CommonName = csr.Subject.CommonName
	s.CountryName = utils.Ltos(csr.Subject.Country)
	s.LocalityName = utils.Ltos(csr.Subject.Locality)
	s.OrganizationName = utils.Ltos(csr.Subject.Organization)
	s.OrganizationalUnitName = utils.Ltos(csr.Subject.OrganizationalUnit)
	s.SerialNumber = csr.Subject.SerialNumber // a csr can have a serial number
	s.StateOrProvinceName = utils.Ltos(csr.Subject.Province)

	csrData.Extensions = e
	csrData.KeyType = getKeyType(csr.PublicKey, csr.PublicKeyAlgorithm)
	csrData.SignatureAlgorithm = csr.SignatureAlgorithm.String()
	csrData.Subject = s
	csrData.Version = csr.Version

	return csrData
}

func getSerialString(s *big.Int) string {

	serial := strings.ToUpper(s.Text(16))
	if len(serial) == 31 || len(serial) == 1 {
		serial = "0" + serial
	}

	return serial
}

// VerifyHostname returns bool if hostname is valid for certificate
func VerifyHostname(cert *x509.Certificate, host string) bool {
	matches := false

	err := cert.VerifyHostname(host)
	if err == nil {
		matches = true
	}

	return matches
}
