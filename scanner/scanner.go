package scanner

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	"github.com/jsandas/tlstools/certutil"
	"github.com/jsandas/tlstools/logger"
	"github.com/jsandas/tlstools/ssl"
	"github.com/jsandas/tlstools/ssl/status"
	"github.com/jsandas/tlstools/utils"
	"github.com/jsandas/tlstools/utils/tcputils"
	"github.com/jsandas/tlstools/vuln"
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
	DebianWeakKey bool   `json:"debianWeakKey"`
	Heartbleed    string `json:"heartbleed"`
}

func getCertData(cList []*x509.Certificate, ocspStaple []byte) []certutil.CertData {
	var certs []certutil.CertData
	for i, cert := range cList {
		certData := certutil.ParseCert(cert)
		// check CRLs
		certData.Status.CRL = status.CRL(certData.SerialNumber, certData.Extensions.CRLDistributionPoints)

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
		certData.Status.OCSP = ocspStatus

		certs = append(certs, certData)
		logger.Debugf("event_id=parsed_certificate cn=%s", certData.Subject.CommonName)
	}

	return certs
}

// Scan is performs tls certificate and conn checks
func Scan(host string, port string) Results {
	var results Results
	var connData ConnectionData
	var vulnData Vulnerabilities
	var WG sync.WaitGroup
	var mutex = &sync.Mutex{}
	var service = utils.GetService(port)

	tlsConnState, tlsVers := ssl.ConnState(host, port)
	certs := tlsConnState.PeerCertificates

	if len(certs) == 0 {
		logger.Debugf("event_id=no_certs_found host=%s port=%s", host, port)
		return results
	}

	ocspStapling := tlsConnState.OCSPResponse

	results.Certificates = getCertData(certs, ocspStapling)

	// collect data about the connection in general
	if service == "https" || strings.HasSuffix(service, "SSL") {
		connData.ServerHeader = utils.GetHTTPHeader(host, port, "Server")
	} else {
		connData.ServerHeader = tcputils.GetTCPHeader(host, port)
	}
	connData.HostNameMatches = certutil.VerifyHostname(certs[0], host)
	connData.ChainTrusted = certutil.IsTrusted(certs, host)
	connData.HostName = host
	if ocspStapling != nil {
		connData.OCSPStapling = true
	}

	WG.Add(1)
	go func() {
		keyType := certs[0].PublicKeyAlgorithm.String()
		mutex.Lock()
		connData.SupportedConfig = ssl.Check(host, port, keyType)
		mutex.Unlock()
		WG.Done()
	}()

	vulnData.Heartbleed = vuln.Heartbleed(host, port, tlsVers)

	if certs[0].PublicKeyAlgorithm.String() == "RSA" {
		pubKey := certs[0].PublicKey.(*rsa.PublicKey)
		keySize := pubKey.Size() * 8
		modulus := fmt.Sprintf("%x", pubKey.N)
		vulnData.DebianWeakKey = vuln.DebianWeakKey(keySize, modulus)
	}

	WG.Wait()

	results.ConnectionInformation = connData
	results.Vulnerabilities = vulnData

	return results
}
