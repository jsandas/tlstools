package status

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/pkg/utils"

	"golang.org/x/crypto/ocsp"
)

func checkCRL(certSerial string, crlURI string) (string, error) {
	var isValid = "good"

	// crl, err := downloadBINFile("http://crl3.digicert.com/ssca-sha2-g6.crl")
	crl, err := utils.DownloadBINFile(crlURI)
	if err != nil {
		return "error", err
	}

	pc, err := x509.ParseCRL(crl)
	if err != nil {
		return "error", err
	}

	// check if crl is expired
	e := pc.HasExpired(time.Now().UTC())
	if e {
		return "crl_expired", nil
	}

	// check if serial is revoked
	for _, rc := range pc.TBSCertList.RevokedCertificates {
		// logger.Debugf("server_serial=%d crl_serial=%d", certSerial, revoked.SerialNumber)
		if certSerial == fmt.Sprintf("0%X", rc.SerialNumber) {
			logger.Debugf("event_id=revoked_serial uri=%s serial=%s", crlURI, certSerial)
			isValid = "revoked"
		}
	}

	return isValid, nil
}

// CRL check revocation status via CRL
func CRL(certSerial string, crlDP []string) string {
	status := ""

	for _, crlURL := range crlDP {
		// only check crl published via http
		if strings.HasPrefix(crlURL, "http") {
			crlStatus, err := checkCRL(certSerial, crlURL)
			if err != nil {
				logger.Errorf("event_id=crl_check_failed msg=\"%v\"", err)
			}
			if status == "" {
				status = crlStatus
			}
			if status == "good" {
				status = crlStatus
			}
		}
	}
	logger.Debugf("event_id=crl_check_completed status=%s", status)

	return status
}

// OCSP checks revocation via OCSP
func OCSP(stapleData []byte, cert *x509.Certificate) string {
	var ocspRes []byte
	var status string

	ocspRes = stapleData

	if ocspRes == nil {
		// do not proceed if ocsp server uri is not provided
		uri := utils.Ltos(cert.OCSPServer)
		if uri == "" {
			return "error"
		}

		req, err := createOCSPReq(cert)
		if err != nil {
			logger.Errorf("event_id=ocsp_req_gen_failed cn=\"%s\" msg=\"%v\"", cert.Subject.CommonName, err)
			return "error"
		}

		ocspRes, err = getOCSPResp(req, uri)
		if err != nil {
			logger.Errorf("event_id=ocsp_req_failed cn=\"%s\" msg=\"%v\"", cert.Subject.CommonName, err)
			return "error"
		}
	}

	status, err := checkOCSP(ocspRes, nil)
	if err != nil {
		logger.Errorf("event_id=ocsp_check_failed msg\"%v\"", err)
	}

	logger.Debugf("event_id=ocsp_check_completed status=%s", status)

	return status
}

func createOCSPReq(cert *x509.Certificate) ([]byte, error) {
	var ocspReq []byte
	var ica *x509.Certificate

	if len(cert.IssuingCertificateURL) > 0 {
		var err error
		b, _ := utils.DownloadBINFile(cert.IssuingCertificateURL[0])
		ica, err = x509.ParseCertificate(b)
		if err != nil {
			return ocspReq, err
		}
	} else {
		// Not all certificates have the AIA extension with the CAIssuers field
		// Using golang certificate verification to attempt to create
		// a trust chain using the system roots
		opts := x509.VerifyOptions{}
		chains, err := cert.Verify(opts)
		if err != nil {
			return ocspReq, err
		}
		chain := chains[0]
		ica = chain[len(chain)-1]
	}

	ocspReq, err := ocsp.CreateRequest(cert, ica, nil)
	if err != nil {
		return ocspReq, err
	}

	return ocspReq, nil
}

func checkOCSP(ocspRes []byte, ica *x509.Certificate) (string, error) {
	ocspStatuses := map[int]string{
		0: "successful",
		1: "malformedRequest",
		2: "internalError",
		3: "tryLater",
		5: "sigRequired",
		6: "unauthorized",
		7: "unauthorized",
	}

	// parse ocspRes
	resp, err := ocsp.ParseResponse(ocspRes, nil)
	if err != nil {
		return "", err
	}

	exp := checkOCSPExp(resp.NextUpdate)
	if exp != "valid" {
		return exp, nil
	}

	status := ocspStatuses[resp.Status]

	return status, nil
}

func checkOCSPExp(expiration time.Time) string {
	status := "valid"
	if time.Now().UTC().After(expiration) {
		status := "ocsp_expired"
		return status
	}
	return status
}

func getOCSPResp(request []byte, ocspURI string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, ocspURI, bytes.NewBuffer(request))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")
	req.Header.Add("host", ocspURI)
	req.Header.Set("User-Agent", "SSL_Scanner")
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}
