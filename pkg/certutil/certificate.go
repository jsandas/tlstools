package certutil

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"time"

	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/pkg/utils"
)

// CertData certificate data fields
type CertData struct {
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

// ParseCert used to parse/massage certain data
func (c *CertData) Process(cert *x509.Certificate) {
	// extensions
	var a = make(map[string]string)
	a["CAIssuers"] = utils.Ltos(cert.IssuingCertificateURL)
	a["OCSP"] = utils.Ltos(cert.OCSPServer)
	c.Extensions.AuthorityInformationAccess = a
	c.Extensions.CRLDistributionPoints = cert.CRLDistributionPoints
	c.Extensions.SubjectAlternativeNames = cert.DNSNames

	//fingerprints
	var f = make(map[string]string)
	h := sha1.New()
	h.Write(cert.Raw)
	f["sha1"] = hex.EncodeToString(h.Sum(nil))
	h = sha256.New()
	h.Write(cert.Raw)
	f["sha256"] = hex.EncodeToString(h.Sum(nil))
	c.Fingerprints = f

	// issuer data
	c.Issuer.CommonName = cert.Issuer.CommonName
	c.Issuer.CountryName = utils.Ltos(cert.Issuer.Country)
	c.Issuer.OrganizationalUnitName = utils.Ltos(cert.Issuer.OrganizationalUnit)
	c.Issuer.OrganizationName = utils.Ltos(cert.Issuer.Organization)

	// subject
	c.Subject.CommonName = cert.Subject.CommonName
	c.Subject.CountryName = utils.Ltos(cert.Subject.Country)
	c.Subject.LocalityName = utils.Ltos(cert.Subject.Locality)
	c.Subject.OrganizationName = utils.Ltos(cert.Subject.Organization)
	c.Subject.OrganizationalUnitName = utils.Ltos(cert.Subject.OrganizationalUnit)
	c.Subject.SerialNumber = cert.Subject.SerialNumber
	c.Subject.StateOrProvinceName = utils.Ltos(cert.Subject.Province)

	// other cert data
	c.KeyType = getKeyType(cert.PublicKey, cert.PublicKeyAlgorithm)
	c.SerialNumber = getSerialString(cert.SerialNumber)
	c.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	c.ValidFrom = cert.NotBefore
	c.ValidTo = cert.NotAfter
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
