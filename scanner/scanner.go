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

// ConnectionData information about tls connection
type ConnectionData struct {
	ChainTrusted    bool                `json:"chainTrusted"`
	HostName        string              `json:"hostName"`
	HostNameMatches bool                `json:"hostNameMatches"`
	OCSPStapling    bool                `json:"ocspStapling"`
	ServerHeader    string              `json:"serverHeader"`
	SupportedConfig map[string][]string `json:"supportedConfig"`
}

// Results struct of all data
type Results struct {
	// RevocationStatuses    RevocationResults
	Certificates          []certutil.CertData `json:"certificates"`
	ConnectionInformation ConnectionData      `json:"connectionInformation"`
	Vulnerabilities       Vulnerabilities     `json:"vulnerabilities"`
}

// Vulnerabilities struct of vuln results
type Vulnerabilities struct {
	DebianWeakKey weakkey.DebianWeakKey `json:"debianWeakKey"`
	Heartbleed    heartbleed.Heartbleed `json:"heartbleed"`
	CCSInjection  ccs.CCSInjection      `json:"ccsinjection"`
}

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

// Scan is performs tls certificate and conn checks
func (r *Results) Scan(host string, port string) {
	var WG sync.WaitGroup
	var mutex = &sync.Mutex{}
	var service = utils.GetService(port)

	tlsConnState, tlsVers := ssl.ConnState(host, port)
	certs := tlsConnState.PeerCertificates

	if len(certs) == 0 {
		logger.Debugf("event_id=no_certs_found host=%s port=%s", host, port)
		return
	}

	ocspStapling := tlsConnState.OCSPResponse

	r.Certificates = getCertData(certs, ocspStapling)

	// collect data about the connection in general
	if service == "https" || strings.HasSuffix(service, "SSL") {
		r.ConnectionInformation.ServerHeader, _ = utils.GetHTTPHeader(host, port, "Server")
	} else {
		r.ConnectionInformation.ServerHeader, _ = tcputils.GetTCPHeader(host, port)
	}
	r.ConnectionInformation.HostNameMatches = certutil.VerifyHostname(certs[0], host)
	r.ConnectionInformation.ChainTrusted = certutil.IsTrusted(certs, host)
	r.ConnectionInformation.HostName = host
	if ocspStapling != nil {
		r.ConnectionInformation.OCSPStapling = true
	}

	WG.Add(1)
	go func() {
		keyType := certs[0].PublicKeyAlgorithm.String()
		mutex.Lock()
		r.ConnectionInformation.SupportedConfig = ssl.Check(host, port, keyType)
		mutex.Unlock()
		WG.Done()
	}()

	r.Vulnerabilities.Heartbleed.Check(host, port, tlsVers)

	r.Vulnerabilities.CCSInjection.Check(host, port)

	if certs[0].PublicKeyAlgorithm.String() == "RSA" {
		pubKey := certs[0].PublicKey.(*rsa.PublicKey)
		keySize := pubKey.Size() * 8
		modulus := fmt.Sprintf("%x", pubKey.N)
		r.Vulnerabilities.DebianWeakKey.Check(keySize, modulus)
	}

	WG.Wait()

}
