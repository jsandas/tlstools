package controllers

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/pkg/certutil"
)

// ParserRoutes builds and returns routes for scanning
func ParserRoutes() *chi.Mux {
	r := chi.NewRouter()
	r.Post("/certificate", certHandler)
	r.Post("/csr", csrHandler)
	return r
}

func certHandler(w http.ResponseWriter, r *http.Request) {
	var c certutil.CertData

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	cbytes := buf.Bytes()

	if len(cbytes) == 0 {
		render.Status(r, http.StatusBadRequest)
		m := map[string]string{"400": "no data received"}
		render.JSON(w, r, m)
		return
	}

	block, _ := pem.Decode(cbytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Errorf("event_id=parse_certificate_failed msg=\"%v\"", err)
		render.Status(r, http.StatusBadRequest)
		m := map[string]string{"400": "unable to parse certificate"}
		render.JSON(w, r, m)
		return
	}

	c.Process(cert)

	render.Status(r, http.StatusOK)
	render.JSON(w, r, c)

}

func csrHandler(w http.ResponseWriter, r *http.Request) {
	var c certutil.CSRData

	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)

	cbytes := buf.Bytes()

	if len(cbytes) == 0 {
		render.Status(r, http.StatusBadRequest)
		m := map[string]string{"400": "no data received"}
		render.JSON(w, r, m)
		return
	}

	block, _ := pem.Decode(cbytes)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		logger.Errorf("event_id=parse_csr_failed msg=\"%v\"", err)
		render.Status(r, http.StatusBadRequest)
		m := map[string]string{"400": "unable to parse csr"}
		render.JSON(w, r, m)
		return
	}

	c.Process(*csr)

	render.Status(r, http.StatusOK)
	render.JSON(w, r, c)

}
