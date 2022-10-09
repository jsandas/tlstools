package scanner

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/certutil"
	"github.com/jsandas/tlstools/ssl"
	"github.com/jsandas/tlstools/ssl/status"
	"github.com/jsandas/tlstools/utils"
	"github.com/jsandas/tlstools/utils/tcputils"
	"github.com/jsandas/tlstools/vuln/ccs"
	"github.com/jsandas/tlstools/vuln/heartbleed"
	"github.com/jsandas/tlstools/vuln/weakkey"
)

func getCertData(cList []*x509.Certificate, ocspStaple []byte) []certutil.CertData {
	var certs []certutil.CertData
	for i, cert := range cList {
		var c certutil.CertData
		c.Process(cert)
		// check CRLs
		c.Status.CRL = status.CRL(c.SerialNumber, c.Extensions.CRLDistributionPoints)

		// check ocsp
		var ocspStatus string
		if i == 0 {
			if ocspStaple != nil {
				ocspStatus = status.OCSP(ocspStaple, nil)
			}
		}
		if ocspStatus == "" {
			ocspStatus = status.OCSP(nil, cert)
		}
		c.Status.OCSP = ocspStatus

		certs = append(certs, c)
		logger.Debugf("event_id=parsed_certificate cn=%s", c.Subject.CommonName)
	}

	return certs
}

// CertificateData information about tls connection
type CertificateData struct {
	Certificates    []certutil.CertData `json:"certificates"`
	ChainTrusted    bool                `json:"chainTrusted"`
	HostName        string              `json:"hostName"`
	HostNameMatches bool                `json:"hostNameMatches"`
}

// Vulnerabilities struct of vuln results
type Vulnerabilities struct {
	DebianWeakKey weakkey.DebianWeakKey `json:"debianWeakKey"`
	Heartbleed    heartbleed.Heartbleed `json:"heartbleed"`
	CCSInjection  ccs.CCSInjection      `json:"ccsinjection"`
}

// ScanCertificate is performs tls certificate and conn checks
func (c *CertificateData) ScanCertificate(host string, port string) {

	tlsConnState, _ := ssl.ConnState(host, port)
	certs := tlsConnState.PeerCertificates

	if len(certs) == 0 {
		logger.Debugf("event_id=no_certs_found host=%s port=%s", host, port)
		return
	}

	ocspStapling := tlsConnState.OCSPResponse

	c.Certificates = getCertData(certs, ocspStapling)

	c.HostNameMatches = certutil.VerifyHostname(certs[0], host)
	c.ChainTrusted = certutil.IsTrusted(certs, host)
	c.HostName = host
}

// ConfigurationData information about tls connection
type ConfigurationData struct {
	ChainTrusted    bool                `json:"chainTrusted"`
	HostName        string              `json:"hostName"`
	HostNameMatches bool                `json:"hostNameMatches"`
	OCSPStapling    bool                `json:"ocspStapling"`
	ServerHeader    string              `json:"serverHeader"`
	SupportedConfig map[string][]string `json:"supportedConfig"`
	Vulnerabilities Vulnerabilities     `json:"vulnerabilities"`
}

// ScanConfiguration is performs tls certificate and conn checks
func (cd *ConfigurationData) ScanConfiguration(host string, port string) {
	var WG sync.WaitGroup
	var mutex = &sync.Mutex{}
	var service = utils.GetService(port)

	tlsConnState, tlsVers := ssl.ConnState(host, port)
	certs := tlsConnState.PeerCertificates
	ocspStapling := tlsConnState.OCSPResponse

	if len(certs) == 0 {
		logger.Debugf("event_id=no_certs_found host=%s port=%s", host, port)
		return
	}

	// collect data about the connection in general
	if service == "https" || strings.HasSuffix(service, "SSL") {
		cd.ServerHeader, _ = utils.GetHTTPHeader(host, port, "Server")
	} else {
		cd.ServerHeader, _ = tcputils.GetTCPHeader(host, port)
	}
	cd.HostNameMatches = certutil.VerifyHostname(certs[0], host)
	cd.ChainTrusted = certutil.IsTrusted(certs, host)
	cd.HostName = host
	if ocspStapling != nil {
		cd.OCSPStapling = true
	}

	WG.Add(1)
	go func() {
		keyType := certs[0].PublicKeyAlgorithm.String()
		mutex.Lock()
		cd.SupportedConfig = ssl.Check(host, port, keyType)
		mutex.Unlock()
		WG.Done()
	}()

	cd.Vulnerabilities.Heartbleed.Check(host, port, tlsVers)

	cd.Vulnerabilities.CCSInjection.Check(host, port)

	if certs[0].PublicKeyAlgorithm.String() == "RSA" {
		pubKey := certs[0].PublicKey.(*rsa.PublicKey)
		keySize := pubKey.Size() * 8
		modulus := fmt.Sprintf("%x", pubKey.N)
		cd.Vulnerabilities.DebianWeakKey.Check(keySize, modulus)
	}

	WG.Wait()

}
