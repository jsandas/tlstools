package controllers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	logger "github.com/jsandas/gologger"
	"github.com/jsandas/tlstools/scanner"
	"github.com/jsandas/tlstools/utils"
)

// ScanRoutes builds and returns routes for scanning
func ScanRoutes() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/certificate", scanCertHandler)
	r.Get("/configuration", scanConfigHandler)
	return r
}

func scanCertHandler(w http.ResponseWriter, r *http.Request) {
	var results scanner.CertificateData

	scanHost := r.URL.Query().Get("host")
	scanPort := "443"

	if strings.Contains(scanHost, ":") {
		l := strings.Split(scanHost, ":")
		scanHost = l[0]
		scanPort = l[1]
	}

	if !utils.ValidHost(scanHost) || !utils.ValidPort(scanPort) {
		logger.Warnf("event_id=invalid_hostname host=%s", scanHost)
		render.Status(r, http.StatusBadRequest)

		m := map[string]string{"400": "invalid host or port"}
		render.JSON(w, r, m)
		return
	}

	if !utils.CanConnect(scanHost, scanPort) {
		logger.Warnf("event_id=host_unreachable hostname=%s:%s", scanHost, scanPort)
		render.Status(r, http.StatusBadRequest)

		m := map[string]string{"400": "host unreachable"}
		render.JSON(w, r, m)
		return
	}

	results.ScanCertificate(scanHost, scanPort)

	render.Status(r, http.StatusOK)
	render.JSON(w, r, results)

}

func scanConfigHandler(w http.ResponseWriter, r *http.Request) {
	var results scanner.ConfigurationData

	scanHost := r.URL.Query().Get("host")
	scanPort := "443"

	if strings.Contains(scanHost, ":") {
		l := strings.Split(scanHost, ":")
		scanHost = l[0]
		scanPort = l[1]
	}

	if !utils.ValidHost(scanHost) || !utils.ValidPort(scanPort) {
		logger.Warnf("event_id=invalid_hostname host=%s", scanHost)
		render.Status(r, http.StatusBadRequest)

		m := map[string]string{"400": "invalid host or port"}
		render.JSON(w, r, m)
		return
	}

	if !utils.CanConnect(scanHost, scanPort) {
		logger.Warnf("event_id=host_unreachable hostname=%s:%s", scanHost, scanPort)
		render.Status(r, http.StatusBadRequest)

		m := map[string]string{"400": "host unreachable"}
		render.JSON(w, r, m)
		return
	}

	results.ScanConfiguration(scanHost, scanPort)

	render.Status(r, http.StatusOK)
	render.JSON(w, r, results)

}
