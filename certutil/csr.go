package certutil

import (
	"crypto/x509"

	"github.com/jsandas/tlstools/utils"
)

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

// ParseCSR returns data from provided csr
func (c *CSRData) Process(csr x509.CertificateRequest) {
	// extensions
	c.Extensions.SubjectAlternativeNames = csr.DNSNames

	// subject
	c.Subject.CommonName = csr.Subject.CommonName
	c.Subject.CountryName = utils.Ltos(csr.Subject.Country)
	c.Subject.LocalityName = utils.Ltos(csr.Subject.Locality)
	c.Subject.OrganizationName = utils.Ltos(csr.Subject.Organization)
	c.Subject.OrganizationalUnitName = utils.Ltos(csr.Subject.OrganizationalUnit)
	c.Subject.SerialNumber = csr.Subject.SerialNumber // a csr can have a serial number
	c.Subject.StateOrProvinceName = utils.Ltos(csr.Subject.Province)

	// other csr data
	c.KeyType = getKeyType(csr.PublicKey, csr.PublicKeyAlgorithm)
	c.SignatureAlgorithm = csr.SignatureAlgorithm.String()
	c.Version = csr.Version

}
